/*
* Copyright 2022 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.morpheusdata.msdns

import com.morpheusdata.core.DNSProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.core.util.ConnectionUtils
import com.morpheusdata.core.util.HttpApiClient
import com.morpheusdata.core.util.NetworkUtility
import com.morpheusdata.core.util.SyncTask
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.model.Icon
import com.morpheusdata.model.NetworkDomain
import com.morpheusdata.model.NetworkDomainRecord
import com.morpheusdata.model.NetworkPoolServer
import com.morpheusdata.model.OptionType
import com.morpheusdata.model.TaskResult
import com.morpheusdata.model.projection.NetworkDomainIdentityProjection
import com.morpheusdata.model.projection.NetworkDomainRecordIdentityProjection
import com.morpheusdata.response.ServiceResponse
import groovy.util.logging.Slf4j
import io.reactivex.Single
import io.reactivex.Observable
import org.apache.tools.ant.types.spi.Service
import groovy.json.JsonSlurper
import java.util.regex.*

/**
 * The DNS Provider implementation for Microsoft DNS
 * This contains most methods used for interacting directly with the Microsoft DNS Powershell Modules via Windows Remote
 * Management.
 * 
 * @author Stephen Potts based on original plugin by David Estes
 */
@Slf4j
class MicrosoftDnsProvider implements DNSProvider {

    MorpheusContext morpheusContext
    Plugin plugin
    // discovered DNS integration service type by integration - value is one of local,winrm,wmi
    // workaround as plugin cant persist integration model
    private Map serviceType
    static DEFAULT_TTL = 3600

    MicrosoftDnsProvider(Plugin plugin, MorpheusContext morpheusContext) {
        log.info("MicrosoftDnsProvider: Constructor called")
        this.morpheusContext = morpheusContext
        this.plugin = plugin
        // Store the serviceType - will be moved to Option in future once ServiceResponse honours changes to the integration
        this.serviceType = [:]
    }

    /**
     * Creates a manually allocated DNS Record of the specified record type on the passed {@link NetworkDomainRecord} object.
     * This is typically called outside of automation and is a manual method for administration purposes.
     * @param integration The DNS Integration record which contains things like connectivity info to the DNS Provider
     * @param record The domain record that is being requested for creation. All the metadata needed to create the record
     * should exist here.
     * @param opts any additional options that may be used in the future to configure behavior. Currently unused
     * @return a ServiceResponse with the success/error state of the create operation as well as the modified record.
     */
    @Override
    ServiceResponse createRecord(AccountIntegration integration, NetworkDomainRecord record, Map opts) {

        log.debug("createRecord - Request record: ${record.getProperties()}")
        log.debug("createRecord - Request opts: ${opts}")
        log.info("createRecord - integration ${integration.name} - Received request to create resource record")
        ServiceResponse<NetworkDomainRecord> validateRecord = validateDnsRecord(record)
        if (validateRecord.success) {
            ServiceResponse<NetworkDomainRecord> addResult = new ServiceResponse<NetworkDomainRecord>(true,null,null,record)
            Boolean createPtrRecord = (integration.serviceFlag == null || integration.serviceFlag)
            String zone = record.networkDomain?.name // DNS Zone 
            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String serviceType = getServiceType(integration) // How to access Dns Service for this integration
            try {
                String command = buildAddDnsRecordScript(record.type,record.name,zone,record.content,record.ttl,createPtrRecord,computerName, serviceType)
                def rpcData = executeCommandScript(integration, command)
                if (!rpcData) {
                    log.error("createRecord - integration ${integration.name} - Unable to determine rpcData from Dns Services")  
                    addResult.success = false
                    addResult.error("Unable to determine rpcData from Dns Services - check Credentials are valid")
                    return addResult
                }
                log.info("createRecord - integration ${integration.name} : returned rpcData : ${rpcData}")
                switch (rpcData.status) {
                    case [0, 9715] :
                        // 9715 Fwd created OK failed to create PTR
                        // 0 Created OK
                        addResult.success = true
                        addResult.msg = rpcData.errOut?.message ?: "DNS record created successfully"
                        break
                    default :
                        // Fail all other error codes including 9711 record exists 
                        log.warn("createRecord - integration ${integration.name} - Failed to create DNS Resource Record ${rpcData}")
                        addResult.success = false
                        addResult.error = rpcData.errOut?.message ?: "Failed to create DNS Resource Record"
                        addResult.data = record  
                        return addResult                
                        break
                }
                // On success the rpcData.cmdOut will contain the DNS Record created
                if (rpcData.cmdOut) {
                    def returnedDnsRecords = rpcData.cmdOut
                    log.debug("createRecord - Rpc Process returned matching newDnsRecords : ${returnedDnsRecords}")
                    def newDnsRecord = returnedDnsRecords.find {(it.recordData.startsWithIgnoreCase(record.content))}
                    if (newDnsRecord) {
                        // update name and recordData from confirmed response
                        def recordData = newDnsRecord.recordData
                        record.name = newDnsRecord.hostName
                        record.internalId = recordData
                        record.externalId = newDnsRecord.distinguishedName
                        record.content = recordData
                        record.recordData = recordData
                        log.info("createRecord - integration ${integration.name} - Successfully created ${record.type} record - host: ${record.name}, zone: ${zone}, data: ${recordData}")
                        addResult.success = true
                        addResult.msg = "Successfully created ${record.type} record ${record.name} in zone ${zone} data ${recordData}"
                        addResult.data = record
                    } else {
                        log.warn("createRecord - integration ${integration.name} - Failed to confirm Resource Record was created as requested")
                        addResult.success = false
                        addResult.error = "Failed to confirm Resource Record was created as Requested"
                        addResult.data = record                     
                    } 
                } else {
                    addResult.success = false
                    addResult.error = "Failed to verify the record properties with the DNS Service"
                    addResult.data = record                    
                }
                return addResult 
            } 
            catch(e) {
                log.error("createRecord - integration ${integration.name} Adding DNS - Exception Raised : ${e.getMessage()}")
                addResult.success = false
                addResult.error = e.getMessage()
                addResult.data = record    
                return addResult                
            }
        } else {
            log.error("createRecord - integration ${integration.name} - DNS Record failed validation. ServiceResponse:  ${validateRecord}")
            return validateRecord
        } 
    }

    /**
     * Deletes a Zone Record that is specified on the Morpheus side with the target integration endpoint.
     * This could be any record type within the specified integration and the authoritative zone object should be
     * associated with the {@link NetworkDomainRecord} parameter.
     * @param integration The DNS Integration record which contains things like connectivity info to the DNS Provider
     * @param record The zone record object to be deleted on the target integration.
     * @param opts opts any additional options that may be used in the future to configure behavior. Currently unused
     * @return the ServiceResponse with the success/error of the delete operation.
     */
    @Override
    ServiceResponse deleteRecord(AccountIntegration integration, NetworkDomainRecord record, Map opts) {

        log.debug("deleteRecord - Request record: ${record.getProperties()}")
        log.debug("deleteRecord - Request opts: ${opts}")
        log.info("deleteRecord - integration ${integration.name} - Received request to delete resource record")
        ServiceResponse<NetworkDomainRecord> deleteResult = new ServiceResponse<NetworkDomainRecord>(true,null,null,record)

        try {
            String rrType = record.type
            String fqdn = record.fqdn
            String name = record.name
            String recordData = record.recordData
            String zone = record.networkDomain.name

            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String serviceType = getServiceType(integration) // How to access Dns Service for this integration
            String command = buildRemoveDnsServerRecordScript(rrType,name,zone,recordData,computerName,serviceType)
            def rpcData = executeCommandScript(integration, command)
            if (!rpcData) {
                log.error("deleteRecord - integration: ${integration.name} - Unable to determine rpcData from Dns Services")
                deleteResult.success = false
                deleteResult.addError("Unable to determine rpcData returned from Dns Services")
                return deleteResult
            }
            log.info("deleteRecord - integration ${integration.name} : rpcData : ${rpcData}")
            switch (rpcData.status) {
                case 9714 :
                    //9714 DNS Record does not Exist - return success response to have Morpheus delete its copy
                    deleteResult.success = true
                    deleteResult.msg = rpcData.errOut.message
                    log.warn("deleteRecord - integration ${integration.name} - Record does not exist in DNS - removing Morpheus copy")
                    return deleteResult
                    break
                case 0 :
                    deleteResult.success = true
                    deleteResult.msg = "Successfully removed ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}"
                    log.info("deleteRecord - integration: ${integration.name} - Successfully removed ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}")
                    return deleteResult
                    break
                default :
                    deleteResult.success = false
                    deleteResult.addError(rpcData.errOut.message)
                    log.error("deleteRecord - integration: ${integration.name} - Error removing ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData} - errOut: ${rpcData.errOut}")
                    return deleteResult
                    break
            }         
        } 
        catch(e) {
            log.error("deleteRecord - integration: ${integration.name} error: ${e}", e)
            deleteResult.success = false
            deleteResult.addError("System Error removing Microsoft DNS Record ${record.name} - ${e.getMessage()}")            
            return deleteResult
        }
    }


    /**
     * Periodically called to refresh and sync data coming from the relevant integration. Most integration providers
     * provide a method like this that is called periodically (typically 5 - 10 minutes). DNS Sync operates on a 10min
     * cycle by default. Useful for caching Host Records created outside of Morpheus.
     */
    @Override
    void refresh(AccountIntegration integration) {
        try {
            def rpcConfig = getRpcConfig(integration)
            def hostOnline = ConnectionUtils.testHostConnectivity(rpcConfig.host, rpcConfig.port ?: 5985, false, true, null)
            log.info("refresh - integration ${integration.name} - checking the integration is online - ${rpcConfig.host} - ${hostOnline}") 
            if(hostOnline) {
                ServiceResponse testDns = testDnsService(integration)
                if (testDns.success) {
                    Date now = new Date()
                    cacheZones(integration)
                    cacheZoneRecords(integration)
                    log.info("refresh - integration: ${integration.name} - Sync Completed in ${new Date().time - now.time}ms")
                    getMorpheus().getIntegration().updateAccountIntegrationStatus(integration, AccountIntegration.Status.ok).subscribe().dispose()
                } else {
                    log.warn("refresh - integration: ${integration.name} - Cannot access DNS Services via integration. Error : ${testDns}")
                    getMorpheus().getIntegration().updateAccountIntegrationStatus(integration, AccountIntegration.Status.error, "Microsoft DNS integration ${integration.name} failed Service Tests")
                }
            } else {
                log.warn("refresh - integration: ${integration.name} - Integration appears to be offline")
                getMorpheus().getIntegration().updateAccountIntegrationStatus(integration, AccountIntegration.Status.error, "Microsoft DNS integration ${integration.name} ${integration.serviceUrl} is unreachable")
            }                       
        } catch(e) {
            log.error("refresh - integration: ${integration.name} - Exception raised refreshing integration ${e.getMessage()}")
        }
    }

    /**
     * Validation Method used to validate all inputs applied to the integration of an DNS Provider upon save.
     * If an input fails validation or authentication information cannot be verified, Error messages should be returned
     * via a {@link ServiceResponse} object where the key on the error is the field name and the value is the error message.
     * If the error is a generic authentication error or unknown error, a standard message can also be sent back in the response.
     * NOTE: This is unused when paired with an IPAMProvider interface
     * @param integration The Integration Object contains all the saved information regarding configuration of the DNS Provider.
     * @param opts any custom payload submission options may exist here
     * @return A response is returned depending on if the inputs are valid or not.
     */
    @Override
    ServiceResponse verifyAccountIntegration(AccountIntegration integration, Map opts) {

        ServiceResponse<AccountIntegration> verify = new ServiceResponse(false,null,null,integration)
        String computerName
        String command

        // config.zoneFilter is the glob style filter for importing zones
        // config.serviceType will be maintained by the plugin (local,winrm,wmi)
        def config = integration.getConfigMap()
        //def credentialService = morpheusContext.getAccountCredential()
        log.debug("verifyAccountIntegration - Validating integration: ${integration.getProperties()} - opts: ${opts}")
        log.info("verifyAccountIntegration - integration: ${integration.name} - serviceUrl: ${integration.serviceUrl}, servicePath: ${integration.serviceUrl}, config: ${config}")
        try {
            // Validate Form options
            verify.errors = [:]
            if(!integration.name || integration.name == ''){
                verify.errors['name'] = 'name is required'
            }
            if(!integration.serviceUrl || integration.serviceUrl == ''){
                verify.errors['serviceUrl'] = 'DNS Server is required'
            }
            if((!integration.servicePassword || integration.servicePassword == '') && (!integration.credentialData?.password || integration.credentialData?.password == '')){
                verify.errors['servicePassword'] = 'password is required'
            }
            if((!integration.serviceUsername || integration.serviceUsername == '') && (!integration.credentialData?.username || integration.credentialData?.username == '')){
                verify.errors['serviceUsername'] = 'username is required'
            }
            if (config.zoneFilter) {
                def zoneFilters = config.zoneFilter.tokenize(",").each {
                    if (!makeZoneFilterRegex(it)) {
                        verify.errors["zoneFilter"] = "Invalid Zone Filter. Use comma separated list of zones to import in this format: *.mydomain.com, *.10.in-addr.arpa"
                    }
                }
            }
            if (verify.errors.size() > 0) {
                // Errors on form - return these errors now
                log.error("verifyAccountIntegration - integration: ${integration.name}. Form validation errors while Adding Integration: ${verify.errors}")
                verify.success = false
                return verify
            }
            // Validate connectivity to serviceUrl over WinRM - return immediately on a fail
            log.info("verifyAccountIntegration - integration: ${integration.name} - checking winRm on serviceUrl: ${integration.serviceUrl}")
            def serviceHostOnline = ConnectionUtils.testHostConnectivity(integration.serviceUrl, 5985, false, true, null)
            if (!serviceHostOnline) {
                log.warn("verifyAccountIntegration - integration: ${integration.name} - no winRm connectivity to serviceUrl: ${integration.serviceUrl}")
                verify.errors["serviceUrl"] = "serviceUrl ${integration.serviceUrl} not reachable over WinRM (port 5985)"
                verify.success = false
                return verify
            }
            // Form validates OK - Test the DNS Service
            ServiceResponse testDns = testDnsService(integration)
            log.debug("verifyAccountIntegration - integration: ${integration.name} - testDnsService ServiceResponse : ${testDns}")
            if (!testDns.success) {
                log.error("verifyAccountIntegration - integration: ${integration.name} - failed to access Dns Services")
                // just return the ServiceResponse from failed tests - it should be same type
                return testDns
            } else {
                // Dns Service Test are good - update ServiceResponse with test result data
                verify.setData(testDns.data)
            }
            // Catch any errors here
            if(verify.errors.size() > 0) {
                //Report Validation errors
                log.error("verifyAccountIntegration - integration: ${integration.name}. Form validation errors while Adding Integration: ${verify.errors}")
                verify.success = false
                return verify
            }
            log.info("verifyAccountIntegration - Integration: ${integration.name} DNS Services validated OK")
            verify.success = true
            verify.msg = "DNS Integration validated OK "
            log.info("verifyAccountIntegration - Integration: ${integration.name} - Updated integration ServiceResponse ${verify.data.getProperties()}" )
            return verify
        } catch(e) {
            log.error("verifyAccountIntegration - Integration: ${integration.name} : Raised Exception ${e}")
            verify.success = false
            verify.addError(e.getMessage() ?: "Unknown exception raised in verifyAccountIntegration")
            return verify
        }
    }

     // Cache Zones methods
    def cacheZones(AccountIntegration integration, Map opts = [:]) {
        try {
            def listResults = listZones(integration)

            if (listResults.success) {
                List apiItems = listResults.zoneList as List<Map>
                Observable<NetworkDomainIdentityProjection> domainRecords = morpheus.network.domain.listIdentityProjections(integration.id)

                SyncTask<NetworkDomainIdentityProjection,Map,NetworkDomain> syncTask = new SyncTask(domainRecords, apiItems as Collection<Map>)
                syncTask.addMatchFunction { NetworkDomainIdentityProjection domainObject, Map apiItem ->
                    domainObject.externalId == apiItem['zoneName']
                }.onDelete {removeItems ->
                    morpheus.network.domain.remove(integration.id, removeItems).blockingGet()
                }.onAdd { itemsToAdd ->
                    addMissingZones(integration, itemsToAdd)
                }.withLoadObjectDetails { List<SyncTask.UpdateItemDto<NetworkDomainIdentityProjection,Map>> updateItems ->
                    Map<Long, SyncTask.UpdateItemDto<NetworkDomainIdentityProjection, Map>> updateItemMap = updateItems.collectEntries { [(it.existingItem.id): it]}
                    return morpheus.network.domain.listById(updateItems.collect{it.existingItem.id} as Collection<Long>).map { NetworkDomain networkDomain ->
                        SyncTask.UpdateItemDto<NetworkDomainIdentityProjection, Map> matchItem = updateItemMap[networkDomain.id]
                        return new SyncTask.UpdateItem<NetworkDomain,Map>(existingItem:networkDomain, masterItem:matchItem.masterItem)
                    }
                }.onUpdate { List<SyncTask.UpdateItem<NetworkDomain,Map>> updateItems ->
                    updateMatchedZones(integration, updateItems)
                }.start()
            }
        } catch (e) {
            log.error("cacheZones error: ${e}", e)
        }
    }   

    /**
     * Creates a mapping for networkDomainService.createSyncedNetworkDomain() method on the network context.
     * @param integration
     * @param addList
     */
    void addMissingZones(AccountIntegration integration, Collection addList) {
        List<NetworkDomain> missingZonesList = addList?.collect { Map zone ->
            NetworkDomain networkDomain = new NetworkDomain()
            networkDomain.externalId = zone['zoneName']
            networkDomain.name = NetworkUtility.getFriendlyDomainName(zone['zoneName'] as String)
            networkDomain.fqdn = NetworkUtility.getFqdnDomainName(zone['zoneName'] as String)
            networkDomain.refSource = 'integration'
            networkDomain.zoneType = 'Authoritative'
            networkDomain.publicZone = true
            log.info("Adding Zone: ${networkDomain}")
            return networkDomain
        }
        morpheus.network.domain.create(integration.id, missingZonesList).blockingGet()
    }

    /**
     * Given an AccountIntegration (integration) and updateList, update NetwordDomain zone records
     * @param integration
     * @param updateList
     */
    void updateMatchedZones(AccountIntegration integration, List<SyncTask.UpdateItem<NetworkDomain,Map>> updateList) {
        def domainsToUpdate = []
        log.info("updateMatchedZones -  update Zones for ${integration.name} - updated items ${updateList.size()}")
        for(SyncTask.UpdateItem<NetworkDomain,Map> update in updateList) {
            NetworkDomain existingItem = update.existingItem as NetworkDomain
            if(existingItem) {
                Boolean save = false
                if(!existingItem.externalId) {
                    existingItem.externalId = update.masterItem['zoneName']
                    save = true
                }

                if(!existingItem.refId) {
                    existingItem.refType = 'AccountIntegration'
                    existingItem.refId = integration.id
                    existingItem.refSource = 'integration'
                    save = true
                }

                if(save) {
                    log.info("updateMatchedZones -  ready to update item ${existingItem}")
                    domainsToUpdate.add(existingItem)
                }
            }
        }
        if(domainsToUpdate.size() > 0) {
            morpheus.network.domain.save(domainsToUpdate).blockingGet()
        }
    }


    // Cache Zones methods
    def cacheZoneRecords(AccountIntegration integration, Map opts=[:]) {

        getMorpheus().getNetwork().getDomain().listIdentityProjections(integration.id).buffer(50).flatMap { Collection<NetworkDomainIdentityProjection> resourceIdents ->
            return getMorpheus().getNetwork().getDomain().listById(resourceIdents.collect{it.id})
        }.flatMap { NetworkDomain domain ->
            def listResults = listRecords(integration,domain)
            log.debug("cacheZoneRecords - domain: ${domain.externalId}, listResults: ${listResults}")

            if (listResults.success) {
                List<Map> apiItems = listResults.recordList as List<Map>

                //Unfortunately the unique identification matching for msdns requires the full record for now... so we have to load all records...this should be fixed

                Observable<NetworkDomainRecord> domainRecords = getMorpheus().getNetwork().getDomain().getRecord().listIdentityProjections(domain,null).buffer(50).flatMap {domainIdentities ->
                    getMorpheus().getNetwork().getDomain().getRecord().listById(domainIdentities.collect{it.id})
                }
                SyncTask<NetworkDomainRecord, Map, NetworkDomainRecord> syncTask = new SyncTask<NetworkDomainRecord, Map, NetworkDomainRecord>(domainRecords, apiItems)
                return syncTask.addMatchFunction {  NetworkDomainRecord domainObject, Map apiItem ->
                    (domainObject.externalId == apiItem['distinguishedName'] && domainObject.internalId == apiItem['recordData']) ||
                            (domainObject.externalId == null && domainObject.type == apiItem['recordType']?.toUpperCase() && domainObject.fqdn == NetworkUtility.getDomainRecordFqdn(apiItem['hostName'] as String, domain.fqdn))

                }.onDelete {removeItems ->
                    log.debug("cacheZoneRecords - Removing domain record ${removeItems}")
                    getMorpheus().getNetwork().getDomain().getRecord().remove(domain, removeItems).blockingGet()
                }.onAdd { itemsToAdd ->
                    addMissingDomainRecords(domain, itemsToAdd)
                }.withLoadObjectDetails { List<SyncTask.UpdateItemDto<NetworkDomainRecord,Map>> updateItems ->
                    Map<Long, SyncTask.UpdateItemDto<NetworkDomainRecord, Map>> updateItemMap = updateItems.collectEntries { [(it.existingItem.id): it]}
                    return getMorpheus().getNetwork().getDomain().getRecord().listById(updateItems.collect{it.existingItem.id} as Collection<Long>).map { NetworkDomainRecord domainRecord ->
                        SyncTask.UpdateItemDto<NetworkDomainRecordIdentityProjection, Map> matchItem = updateItemMap[domainRecord.id]
                        return new SyncTask.UpdateItem<NetworkDomainRecord,Map>(existingItem:domainRecord, masterItem:matchItem.masterItem)
                    }
                }.onUpdate { List<SyncTask.UpdateItem<NetworkDomainRecord,Map>> updateItems ->
                    updateMatchedDomainRecords(updateItems)
                }.observe()
            } else {
                log.info("cacheZoneRecords - No data to sync for ${domain.externalId}")
                return Single.just(false)
            }
        }.doOnError{ e ->
            log.error("cacheZoneRecords error: ${e}", e)
        }.subscribe()

    }

    void updateMatchedDomainRecords(List<SyncTask.UpdateItem<NetworkDomainRecord, Map>> updateList) {
        def records = []
        updateList?.each { update ->
            NetworkDomainRecord existingItem = update.existingItem
            String recordType = update.masterItem.rr_type
            if(existingItem) {
                //update view ?
                def save = false
                if(existingItem.externalId == null) {
                    existingItem.externalId = update.masterItem['distinguishedName']
                    existingItem.internalId = update.masterItem['recordData']
                    save = true
                }
                if(existingItem.content != update.masterItem['recordData']) {
                    existingItem.content = update.masterItem['recordData']
                    save = true
                }

                if(save) {
                    records.add(existingItem)
                    log.debug("updateMatchedDomainRecords - Updating record id: ${existingItem.id} with ${update.masterItem}")
                } else {
                    log.debug("updateMatchedDomainRecords - Skipping record id: ${existingItem.id}")
                }
            }
        }
        if(records.size() > 0) {
            morpheus.network.domain.record.save(records).blockingGet()
        }
    }

    void addMissingDomainRecords(NetworkDomain domain, Collection<Map> addList) {
        List<NetworkDomainRecord> records = []

        addList?.each {record ->
            if(record['hostName']) {
                def addConfig = [networkDomain:new NetworkDomain(id: domain.id), fqdn:NetworkUtility.getDomainRecordFqdn(record['hostName'] as String, domain.fqdn),
                                 type:record['recordType']?.toUpperCase(), comments:record.comments, ttl:convertTtlStringToSeconds(record['timeToLive']),
                                 externalId:record['distinguishedName'], internalId:record['recordData'], source:'sync',
                                 recordData:record['recordData'], content:record['recordData']]
                if(addConfig.type == 'SOA' || addConfig.type == 'NS')
                    addConfig.name = record['hostName']
                else
                    addConfig.name = NetworkUtility.getFriendlyDomainName(record['hostName'] as String)
                def add = new NetworkDomainRecord(addConfig)
                records.add(add)
                log.debug("addMissingDomainRecords - Adding ${add.getProperties()}")
            }

        }
        morpheus.network.domain.record.create(domain,records).blockingGet()
    }

    /**
     * Provide custom configuration options when creating a new {@link AccountIntegration}
     * @return a List of OptionType
     */
    @Override
    List<OptionType> getIntegrationOptionTypes() {
        return [
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.serviceUrl', 
                    name: 'Service URL', 
                    inputType: OptionType.InputType.TEXT, 
                    fieldName: 'serviceUrl', 
                    fieldLabel: 'RPC Server', 
                    fieldContext: 'domain', 
                    required: true,
                    helpText: 'Name of the server providing access to MS DNS Services. May also be the DNS Server', 
                    displayOrder: 0
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.credentials', 
                    name: 'Credentials', 
                    inputType: OptionType.InputType.CREDENTIAL, 
                    fieldName: 'type', 
                    fieldLabel: 'Credentials', 
                    fieldContext: 'credential', 
                    required: true, 
                    displayOrder: 1, 
                    defaultValue: 'local',
                    optionSource: 'credentials',
                    config: '{"credentialTypes":["username-password"]}'
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.serviceUsername', 
                    name: 'Service Username', 
                    inputType: OptionType.InputType.TEXT, 
                    fieldName: 'serviceUsername', 
                    fieldLabel: 'Username', 
                    fieldContext: 'domain', 
                    required: true, 
                    displayOrder: 2,
                    localCredential: true
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.servicePassword', 
                    name: 'Service Password', 
                    inputType: OptionType.InputType.PASSWORD, 
                    fieldName: 'servicePassword', 
                    fieldLabel: 'Password', 
                    fieldContext: 'domain', 
                    required: true, 
                    displayOrder: 3,
                    localCredential: true
                ),
                new OptionType(
                    code:'accountIntegration.microsoft.dns.servicePath', 
                    inputType: OptionType.InputType.TEXT, 
                    name:'servicePath', 
                    category:'accountIntegration.microsoft.dns',
                    fieldName:'servicePath',
                    fieldLabel:'DNS Server', 
                    fieldContext:'domain', 
                    required:false, 
                    enabled:true, 
                    editable:true, 
                    global:false,
                    placeHolder:null,
                    helpBlock:'Name of DNS Server. Integration will use RPC Server is left blank', 
                    defaultValue:null, 
                    custom:false, 
                    displayOrder:75
                ),
                new OptionType(
                    code:'accountIntegration.microsoft.dns.serviceFlag', 
                    inputType: OptionType.InputType.CHECKBOX, 
                    name:'serviceFlag', 
                    category:'accountIntegration.microsoft.dns',
                    fieldName:'serviceFlag', 
                    fieldCode: 'gomorpheus.label.dnsPointerCreate', 
                    fieldLabel:'Create Pointers', 
                    fieldContext:'domain', 
                    required:false, 
                    enabled:true, 
                    editable:true, 
                    global:false,
                    placeHolder:null, 
                    helpBlock:'', 
                    defaultValue:'on', 
                    custom:false, 
                    displayOrder:80
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.zoneFilter', 
                    name: 'Zone Filter', 
                    inputType: OptionType.InputType.TEXT, 
                    fieldName: 'zoneFilter', 
                    fieldLabel: 'Zone Filter', 
                    required: false,
                    helpText: 'Comma separated string of glob style zone names to import. All zones are imported if blank',
                    fieldContext:'config',
                    displayOrder: 70
                ),
                // Store the serviceType (local,winrm,wmi) - maintained by the plugin does not require user input
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.serviceType', 
                    name: 'Service Type', 
                    inputType: OptionType.InputType.HIDDEN, 
                    fieldName: 'serviceType', 
                    fieldLabel: 'Service Type', 
                    required: false,
                    defaultValue: 'local', 
                    fieldContext:'config',
                    displayOrder: 76
                )                               
        ]
    }

    /**
     * Returns the IPAM Integration logo for display when a user needs to view or add this integration
     * @since 0.12.3
     * @return Icon representation of assets stored in the src/assets of the project.
     */
    @Override
    Icon getIcon() {
        return new Icon(path:"microsoft.dns.svg", darkPath: "microsoft.dns.svg")
    }

    /**
     * Returns the Morpheus Context for interacting with data stored in the Main Morpheus Application
     *
     * @return an implementation of the MorpheusContext for running Future based rxJava queries
     */
    @Override
    MorpheusContext getMorpheus() {
        return morpheusContext
    }

    /**
     * Returns the instance of the Plugin class that this provider is loaded from
     * @return Plugin class contains references to other providers
     */
    @Override
    Plugin getPlugin() {
        return plugin
    }

    /**
     * A unique shortcode used for referencing the provided provider. Make sure this is going to be unique as any data
     * that is seeded or generated related to this provider will reference it by this code.
     * @return short code string that should be unique across all other plugin implementations.
     */
    @Override
    String getCode() {
        return "microsoft.dns"
    }

    /**
     * Provides the provider name for reference when adding to the Morpheus Orchestrator
     * NOTE: This may be useful to set as an i18n key for UI reference and localization support.
     *
     * @return either an English name of a Provider or an i18n based key that can be scanned for in a properties file.
     */
    @Override
    String getName() {
        return "Microsoft DNS"
    }

    // Getters and Setters for storage of serviceType by integration ID
    def getServiceType(AccountIntegration integration) {
        if (this.serviceType.containsKey(integration.id)) {
            return this.serviceType.get(integration.id)
        } else {
            log.error("getServiceType - Integration ${integration.name} with id: ${integration.id} Requires a Service Type. Defaulting to local. Please re-save the integration to set a service type")
            return "local"
        }
    }

    def setServiceType(AccountIntegration integration, String serviceType) {
        this.serviceType.put(integration.id,serviceType)
    }

    def listZones(AccountIntegration integration) {

        def rtn = [success:false, zoneList:[]]
        def zoneFilters //holds an array of RegEx patterns. Zones matching any filter will be imported
        def config = integration.getConfigMap()
        zoneFilters = config.zoneFilter ? config.zoneFilter.tokenize(",").collect {makeZoneFilterRegex(it)} : null 
        
        try {
            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String serviceType = getServiceType(integration) // How to access Dns Service for this integration            
            String command = buildGetDnsZoneScript(computerName,serviceType)
            def rpcData = executeCommandScript(integration, command)

            if (rpcData?.status == 0) {
                log.debug("listZones - integration ${integration.name} - rpcData: ${rpcData}")
                def zoneRecords = rpcData.cmdOut
                if (zoneFilters) {
                    log.info("listZones - integration ${integration.name} - Applying glob style zone filters : ${config.zoneFilter} regEx: ${zoneFilters}")
                    def filteredZoneRecords = zoneRecords.collect {zone -> 
                        // Does this zone name match any of the import zoneFilters
                        if (zoneFilters.find {(zone.zoneName ==~ it)}) {
                            log.info("listZones - integration ${integration.name} - found matching zone: {$zone.zoneName}")
                            return zone
                        } else {
                            log.warn("listZones - integration ${integration.name} - Skipping non-matching zone: {$zone.zoneName}")
                        }                      
                    }.findAll()                
                    rtn.zoneList = filteredZoneRecords
                    rtn.success = true
                } else {
                    log.info("listZones - integration ${integration.name} - No Zone filter - importing all zones")
                    rtn.zoneList = zoneRecords
                    rtn.success = true
                }
            } else {
                log.error("listZones - integration ${integration.name} - Failed to get Dns Zone list status: ${rpcData.status} - details ${rpcData.errOut}")
            }
        } catch(e) {
            log.error("listZones  - integration ${integration.name} raised exception error: ${e.getMessage()}")
        }
        return rtn
    }

    def listRecords(AccountIntegration integration, NetworkDomain domain) {

        def rtn = [success:false, recordList:[]]
        try {
            log.info("listRecords - integration ${integration.name} - importing zone ${domain.externalId}")
            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String serviceType = getServiceType(integration) // How to access Dns Service for this integration            
            String command = buildGetDnsResourceRecordScript(domain.externalId,computerName,serviceType)
            def rpcData = executeCommandScript(integration, command)
            if (rpcData?.status == 0) {
                rtn.success = true
                rtn.recordList = rpcData.cmdOut
                log.info("listRecords - integration ${integration.name} - zone: ${domain.externalId} resourceRecords: ${rtn.recordList.size()}")
            }
            else {
                log.error("listRecords - integration ${integration.name} - zone: ${domain.externalId} - status: ${rpcData.status} - details: ${rpcData.errOut}")
            }
        } catch(e) {
            log.error("listRecords - integration ${integration.name} raised error: ${e.getMessage()}")
        }
        return rtn
    }

    def getDnsServiceProperties(AccountIntegration integration) {
        def rpcData = [status:1, errOut:null, cmdOut: null]
        String command
        try {
            log.info("getDnsServiceProperties - integration ${integration.name} - attempting to discovering Dns Service properties")
            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            command = buildTestDnsServiceScript(computerName)
            rpcData = executeCommandScript(integration,command)
            log.info("getDnsServiceProperties - integration ${integration.name} - Discovery status: ${rpcData}")
        } catch(e) {
            log.error("getDnsServiceProperties - integration ${integration.name} raised exception: ${e.getMessage()}")
        }
        return rpcData      
    }

    /**
     * Wrapper method to execute the custom built Powershell command string via the Morpheus rpc process
     * and handle the custom response for this plugin. Powershell Commands return a json string interpreted 
     * and transformed into a Map object by handleTaskResult()
     */
    Map executeCommandScript(AccountIntegration integration, String commandScript) {

        TaskResult results // Morpheus Rpc service result
        log.debug("executeCommandScript - Integration : ${integration.name} Ready to execute commandScript")
        def computerName = integration.servicePath
        def commandOpts = getRpcConfig(integration, computerName)
        results = executeCommand(commandScript, commandOpts)
        // inspect the Morpheus rpc TaskResult for the custom rpcData
        return handleTaskResult(results)
    }

    /**
     * execute command string over the Morpheus RPC process
     * @param command
     * @param opts 
     */
    TaskResult executeCommand(String command, Map opts) {
        def winrmPort = opts.port && opts.port != 22 ? opts.port : 5985

        def dns = [:]
        TaskResult result
        log.debug("executeCommand - command: ${command}")
        log.debug("executeCommand - Using command parameter opts: ${opts}")

        try {
            result = getMorpheus().executeWindowsCommand(opts.host,winrmPort,opts.username,opts.password,command,true,opts.elevated ? true: false).blockingGet()
            log.debug("executeCommand TaskResult ${result.toMap()}")
            // Check for any Microsoft DNS service error codes
            if (result.success) {
                log.debug("executeCommand - Microsoft DNS Rpc process on host ${opts.host} completed successfully. Process exitCode ${result.exitCode}")
                result.msg = "Remote Process completed successfully"
            } else {
                //Did the remote process actually connect - check exitCode: null indicates failed to establish a connection 
                if (result.exitCode) {
                    log.warn("executeCommand - Remote Process on host ${opts.host} returned exitCode ${result.exitCode}")
                    result.error = "Remote Process returned a non-zero exit code ${result.exitCode}"
                } else {
                    result.error = "Remote Process failed to connect to host with the credentials supplied"
                    log.error("executeCommand - Rpc process failed to host ${opts.host} with the credentials supplied ${opts.username}")
                }
            }
        }
        catch (e) {
            log.warn("executeCommand - Rpc process raised exception - ${e}")
            result.error = "executeCommand raised exception ${e.getMessage()}"
        }
        return result
    }

    /**
     * Generalizes the remote connection information from credential data
     * @param integration
     * @param computerName
     */
    private getRpcConfig(AccountIntegration integration, String computerName=null) {
        def credentialService = getMorpheus().getAccountCredential()
        log.debug("getRpcConfig - integration: ${integration.name} - credentialData : ${integration.credentialData}")
        def rtn = [:]
        rtn.host = integration.serviceUrl
        rtn.port = integration.servicePort ?: 5985
        rtn.username = integration.credentialData?.username ?: integration.serviceUsername
        rtn.password = integration.credentialData?.password ?: integration.servicePassword
        //rtn.elevated = computerName ? true : false
        rtn.elevated = false // never use the JRuby if possible
        //rtn.servicePath = integration.serviceMode???
        log.debug("getRpcConfig - integration: ${integration.name} - rtn: ${rtn}")
        return rtn
    }

    private Integer convertTtlStringToSeconds(String ttlInput) {
        if(ttlInput) {
            def ttlArgs = ttlInput?.tokenize(':')?.reverse()
            Integer ttl = 0
            for(int x =0 ; x<ttlArgs.size();x++) {
                def ttlVal = ttlArgs[x] ? Double.parseDouble(ttlArgs[x]).intValue() : null
                if(ttlVal) {
                    if(x == 0) {
                        ttl += ttlVal
                    } else if(x == 1) {
                        ttl += (ttlVal*60)
                    } else if(x == 2) {
                        ttl += (ttlVal * 60 * 60)
                    } else if(x == 3) {
                        ttl += (ttlVal * 60 * 60 * 24)
                    }
                }
            }
            return ttl
        } else {
            return 0
        }
    }

    /**
    * TaskResult exitCode is not always set by the rpc service to the DNS Cmdlet error code
    * In this implementation, the Microsoft DNS Error Code (non zero) if raised will be returned as part
    * of a json string in the TaskResult data property
    * 
    * taskResult.data = {
    *   "status": "<rpc error code or 0>, 
    *   "cmdOut": "<cmdlet output list>" , 
    *   "errOut": {error object containing detailed Microsoft properties and mandatory message property containing error text}
    * }
    *
    * A null response usually signals an rpc connection failure. Return status 1 with appropriate message
    * otherwise Common Microsoft DNS Error codes are:
    *
    * 9711 DNS fwd record already exists
    * 9714 DNS Record does not exist
    * 9715 Could not create PTR Record (raise when -CreatePtr is added and a record already exists)
    * 9601 DNS zone does not exist.
    * 9563 The record could not be created because this part of the DNS namespace has been delegated to another server
    * 1722 The server is not a DNS Server - the rpc server is unavailable
    */
    Map handleTaskResult(TaskResult result) {

        def jsonSlurper = new JsonSlurper()
        def rpcData = [:]
        
        // Inspect TaskResult data property for a valid response from the Rpc process
        if (result?.data) {
            try {
                log.debug("handleTaskResult - Raw json rpcData ${result.data}")
                rpcData = jsonSlurper.parseText(result.data)
                log.debug("handleTaskResult - MicrosoftDns Rpc result Status ${rpcData}")
            }
            catch (e) {
                log.warn("handleTaskResult - Unable to process MicrosoftDns return json. TaskResult exitCode: ${result.exitCode} - exception ${e}")
                rpcData.status = 1
                rpcData.cmdOut = null
                rpcData.errOut = [message: "Unable to interpret the Rpc json response ${e.getMessage()}"] 
            }
        } else {
            log.error("handleTaskResult - MicrosoftDns Rpc result returned no usable data. TaskResult exitCode: ${result.exitCode}")
            rpcData.status = 1
            rpcData.cmdOut = null
            rpcData.errOut = [message: "Failed to connect to Remote Service with the credentials provided"]
        }        
        return rpcData
    }

    /**
     * Validates the Dns Resource Record
     * returns ServiceResponse
    */
    ServiceResponse validateDnsRecord(NetworkDomainRecord record) {

        Pattern validHost = Pattern.compile('^[a-zA-Z0-9-_\\.]+$')  
        Pattern validPtrHost = Pattern.compile('^[0-9\\.]+$')    
        ServiceResponse<NetworkDomainRecord> ret = new ServiceResponse<NetworkDomainRecord>(true,null,null,record)
        // record must have an associated NetworkDomain - return immediately if no NetworkDomain provided
        try {
            if (!record.networkDomain?.name) {
                ret.success = false
                ret.addError("domain","DNS Domain cannot be null")
                return ret
            }
        }
        catch (e) {
            ret.success = false
            ret.addError("domain","DNS Domain cannot be null")
            return ret
        }
        // Name should be non-qualified host
        record.name = getNQDN(record.name,record.networkDomain?.name)
        // In Microsoft DNS CNAME and PTR targets should end with a trailing .       
        try {
            switch (record.type) {
                case "A" :    
                    if (!(NetworkUtility.validateIpAddr(record.content))) {
                        ret.success = false
                        ret.addError("content","IP v4 Address ${record?.content} is not valid")
                    }
                    if (!(record.name ==~ validHost)) {
                        ret.success = false
                        ret.addError("name","Host ${record.name} is not a valid DNS hostname")
                    } 
                    break
                case "CNAME" : 
                    if (!(record.content ==~ validHost)) {
                        ret.success = false
                        ret.addError("content","CNAME ${record?.content} is not a valid DNS fqdn")
                    } else {
                        if (!(record.content.endsWithIgnoreCase("."))) {
                            record.content = record.content + "."
                        }
                    }
                    if (!(record.name ==~ validHost)) {
                        ret.success = false
                        ret.addError("name","Host ${record.name} is not a valid DNS hostname")
                    } 
                    break
                case "PTR" : 
                    if (!(record.content ==~ validHost)) {
                        ret.success = false
                        ret.addError("content","PTR ${record?.content} is not a valid DNS Reverse fqdn")
                    } else {
                        if (!(record.content.endsWithIgnoreCase("."))) {
                            record.content = record.content + "."
                        }
                    }
                    if (!(record.name ==~ validPtrHost)) {
                        ret.success = false
                        ret.addError("name","Host ${record.name} is not a valid DNS PTR hostname")
                    }                        
                    break
                default :
                    ret.success = false
                    ret.addError("type","Record type ${record.type} is not supported by this Integration plugin")
                    break
            }
            if (record.ttl && record.ttl >= 0) {
                ret.success = true
            } else {
                record.ttl = DEFAULT_TTL
                log.warn("validateDnsRecord - Invalid TTL provided - using default of ${record.ttl}")
                ret.success = true
            }
            if (ret.hasErrors()) {
                // Validation errors found in the new record
                log.error("validateDnsRecord - DNS record failed validation ${ret.getErrors()}")
                ret.success = false
                ret.msg = "DNS Record failed validation"
                ret.data = record
            } else {
                log.info("validateDnsRecord -  DNS record passed validation")
                ret.msg = "DNS record passed validation"
                ret.data = record
            }                    
        }
        catch (e) {
            ret.success = false
            ret.msg = "NetworkDomainRecord validation failed with exception ${e}"
            log.warn("validateDnsRecord - NetworkDomainRecord validation failed with exception ${e}")
        }
        return ret
    }

    /**
     * Validates the Resource Record types that can be added or deleted by this plugin 
     */
    private Boolean supportedRrType(String rrType) {
        if (rrType) {
            def validTypes = ["A","PTR","CNAME"]
            def matchingType = validTypes.findAll {it == rrType.trim().toUpperCase()}
            return (matchingType != [])
        } else {
            return false
        }
    }


    /**
     * Given a hostName and zoneName, retrun a valid Non-Qualified hostname
     * with the zoneName removed
     */
    private String getNQDN(String hostName, String zoneName) {
         
        String nqdn = hostName
        if (zoneName) {
            String zone =  "." + zoneName
            if (hostName.endsWithIgnoreCase(zone)) {
                nqdn = hostName.dropRight(zone.size())
            }
        }
        return nqdn
    }

    /**
     * Construct a regex from a Glob style filter for Zone names
     *
     * eg 
     *.morpheusdata.com for all zones in morpheusdata.com
     *    test*.mydomain.net for all zones beginning test in mydomain.net
    */
    private makeZoneFilterRegex(String globFilter) {

        Pattern globPattern = Pattern.compile('[a-zA-Z0-9-_\\*\\.]*')
        globFilter = globFilter.trim()
        if (globFilter ==~ globPattern) {
            //escape the dots (.) then replace astrix (*)
            def regexFilter = globFilter.replace('.', '\\.').replace('*','[a-zA-Z0-9_-]*')
            // Try compile a regex
            try {
                return Pattern.compile(regexFilter)
            }
            catch (ex) {
                log.error("makeZoneFilterRegex: Invalid regex pattern ${regexFilter} derived from zone filter ${zoneFilter}")
                return null
            }
        } else {
            log.error("makeZoneFilterRegex: Invalid glob pattern for ${globFilter}")
            return null
        }
    }

    /**
     * This method tests if the Morpheus Dns Powershell helper script is available in the %LOCALAPPDATA
     * path in the Service Account user profile. The local copy must match the source md5 chksum to ensure
     * the script file cannot be tampered with. If the helper script file does not exist or fails the chksum 
     * the script is refreshed from the plugin 
     * The helper script has Powershell functions that handle the Microsoft DNS Powershell cmdlets locally
     * or via a jump server
     */
    ServiceResponse testDnsHelperScript(AccountIntegration integration) {
        String runCmd
        log.info("testDnsHelperScript - testing user profile LOCALAPPDATA for Morpheus Dns Helper script ...")
        runCmd = MicrosoftDnsPluginHelper.testHelperFileScript()
        def rtn = executeCommandScript(integration,runCmd)
        if (rtn.status == 9) {
            // Helper script needs to be transferred as its missing or failed the chksum
            log.warn("testDnsHelperScript - Attempting to transfer Helper Script to ${integration.serviceUrl}. rtn.errOut: ${rtn.errOut}")
            def xferRtn = transferDnsHelperScript(integration)
            if (xferRtn.status == 0) {
                log.info("testDnsHelperScript - Successfully transferred Dns Helper Script - re-running tests")
                //try loading the helper script again?
                rtn = executeCommandScript(integration,runCmd)
            } 
        }
        // check status
        if (rtn.status == 0) {
            log.info("testDnsHelperScript - Morpheus Dns Helper Powershell Module successfully loaded on ${integration.serviceUrl} - rtn: ${rtn}")
            return ServiceResponse.success(rtn,"Morpheus Dns Helper Powershell Module successfully loaded on ${integration.serviceUrl}")
        } else {
            log.error("testDnsHelperScript - Error loading Morpheus Dns Helper script ${rtn}")
            return ServiceResponse.error(rtn.errOut.message)
        }  
    } 

     /**
     * This method transfers a Powershell script file containing the Functions needed to support this Integration into the %LOCALAPPDATA
     * path in the Service Account user profile. It helps to overcome the size limitations imposed by the Rpc service
     */       
    private transferDnsHelperScript(AccountIntegration integration) {
        String runCmd
        String contentToXfer = MicrosoftDnsPluginHelper.morpheusDnsHelperScript()
        log.info("transferDnsHelperScript - Preparing to install helper script in 1k fragments")
        def rtn = [status:0,cmdOut:null,errOut:null]
        def i = 0
		while(contentToXfer) {
            log.info("transferDnsHelperScript - transferring support script fragment ${i} ...")
            def chunk = contentToXfer.take(1024)
            contentToXfer = contentToXfer.drop(1024)
            def b64Block = chunk.getBytes("UTF-8").encodeBase64().toString()
            runCmd = MicrosoftDnsPluginHelper.copyHelperBlockScript(b64Block)
            rtn = executeCommandScript(integration,runCmd)
            if(rtn.status != 0) {
                log.warn("transferDnsHelperScript - Failed to transfer support script - ${rtn.errOut}")
                break
            }
            i = i+1
	    }
        return rtn
    }

     /**
     * Tests if the integration can access the DNS Services with the credentials provided either
     * directly (serviceUrl) or via an intermediate server (servicePath).
     * tests comprise these steps
     *   verify the Morpheus Powershell Helper Module is valid chksum
     *   update cached credentials if using an intermediate server
     *   test access to DNS Services
     * Returns a ServiceResponse
     */
    ServiceResponse testDnsService(AccountIntegration integration) {
        String command
        def rpcData
        def computerName = integration.servicePath ?: ""
        def commandOpts = getRpcConfig(integration,computerName)
        
        ServiceResponse<AccountIntegration> rtn = new ServiceResponse(true,null,null,integration)

        // Verify the Morpheus Dns Powershell Helper module and update if required (based on md5 check) 
        ServiceResponse testHelper = testDnsHelperScript(integration)
        log.debug("testDnsService - integration: ${integration.name} testDnsHelperScript ServiceResponse: ${testHelper}")
        if (!testHelper.success) {
            log.error("testDnsService - integration: ${integration.name} - Failed to transfer Morpheus Powershell Helper - check account Credentials - ${testHelper}")
            rtn.errors["serviceUrl"] = "Failed to transfer Morpheus Powershell Helper - check account Credentials for ${integration.serviceUrl}"
            rtn.success = false
            return rtn
        }
        if (integration.servicePath) {
            try {
                //Cache Credentials if using an intermediate server
                log.info("testDnsService - integration: ${integration.name} - Securely caching credential on ${integration.serviceUrl} for onward use on ${integration.servicePath}")
                command = buildCacheCredentialScript(commandOpts.username,commandOpts.password)
                rpcData = executeCommandScript(integration,command)
                if (rpcData?.status > 0) {
                    log.error("testDnsService - integration: ${integration.name} - Failed to securely cache credentials ${rpcData?.errOut?.message}")
                    rtn.addError("serviceUrl","Failed to securely cache credentials for use on ${computerName}")
                    rtn.msg = "Failed to securely cache credentials - error: ${rpcData?.errOut?.message}"
                    return rtn
                } else {
                    log.info("testDnsService - integration: ${integration.name} - Testing access to Dns Services on ${computerName} via ${integration.serviceUrl} using cached credentials")
                }
            }
            catch (e) {
                rtn.success = false
                rtn.addError("Failed to securely cache credentials - error: ${e.getMessage()}")
                log.warn("testDnsService - integration: ${integration.name} Exception caching credentials on ${integration.servicePath} - ${e.getMessage()}")
                return rtn
            }
        } else {
            //DNS Services are local
            log.info("testDnsService - integration: ${integration.name} - Testing access to Dns Services on ${integration.serviceUrl}")
        }
        try {
            rpcData = getDnsServiceProperties(integration)
            // rpcData.cmdOut contains properties about the user, group membership and DNS server version
            if (rpcData?.status > 0) {
                log.error("testDnsService - integration: ${integration.name} - serviceUrl: ${integration.serviceUrl}, servicePath: ${integration.servicePath}. Cannot access MicrosoftDns rpc Services ${rpcData.errOut.message}")
                def errType = computerName ? "servicePath" : "serviceUrl"
                rtn.addError(errType,"Cannot access DNS Services with the Credentials provided. Error : ${rpcData.errOut.message}")
                rtn.msg = "Failed to access Dns Services - error: ${rpcData?.errOut?.message}"
                rtn.success = false
                return rtn            
            } else {
                //local,winrm or wmi serviceType
                // I would like to store it here integration.serviceMode = rpcData.cmdOut?.serviceType
                setServiceType(integration,rpcData.cmdOut?.serviceType)
                integration.setConfigProperty('serviceType',getServiceType(integration))
                log.info("testDnsService - integration: ${integration.name} - serviceUrl: ${integration.serviceUrl}, servicePath: ${integration.servicePath}, serviceType: ${getServiceType(integration)} Dns Services tested OK")
                rtn.success = true
                rtn.msg = "Microsoft Dns Services tested OK"
                return rtn
            }
        }
        catch (e) {
            rtn.success = false
            rtn.addError("Exception raise testing DNS Services : ${e.getMessage()}")
            log.warn("testDnsService - integration: ${integration.name} Exception while testing DNS Services - ${e.getMessage()}")
            return rtn
        }
    }

    /**
     * If using a jump server this Powershell securely caches the credential password in a secure string inside 
     * the profile of the user on the jump server. The credential can only be used by the user who created it and
     * only from the same server (Uses Windows DPAPI)
     * SecureString will be saved to the cache file named %LOCALAPPDATA%\<User SID>-dnsPlugin.ss
     * 
     * Username is the Integration service account 
    */
    private String buildCacheCredentialScript(String username, String password) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def encodedPassword = password.getBytes("UTF-8").encodeBase64().toString()
        def userCmd = '''
        #
        $rtn=Export-MorpheusCredential -Password <%password%>
        '''
        def userScript = userCmd.stripIndent()
            .replace("<%password%>",encodedPassword)
        runCmd = template.replace("<%usercode%>",userScript)
        log.info("buildCacheCredentialScript - Building script to securely cache credentials for ${username}")
        // Dont debug runCmd as it contains creds
        return runCmd        
    }

    /**
     * This Powershell tests access to the Dns Services on the local Dns server or with cached credential via a 
     * jump server
     */
    private String buildTestDnsServiceScript(String computerName) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def userCmd = '''
        #
        $rtn=Test-MorpheusServicePath -Computer "<%computer%>"
        '''
        log.info("buildTestDnsServiceScript - Building script to test access to DNS Services")
        def computer = computerName ?: ""
        def userScript = userCmd.stripIndent()
            .replace("<%computer%>",computer)
        // Load Template and add the userScript
        runCmd = template.replace("<%usercode%>",userScript)
        log.debug("buildTestDnsServiceScript - ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Adding a Dns Resource record
     * Specify the Resource Record to be created (rrType). Supported options can be clearly seen in the switch statement
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     *
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildAddDnsRecordScript(String rrType, String name, String zone, String recordData, Integer ttl, Boolean createPtrRecord, String computerName, String serviceType) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def userCmd = '''
        #
        $Params = @{
            RrType="<%rrtype%>";
            Name="<%name%>";
            Zone="<%zone%>";
            Data="<%data%>";
            Ttl=<%ttl%>;
            CreatePtr=<%createptr%>;
            Computer="<%computer%>";
            ServiceType="<%servicetype%>"
        }
        $rtn=Add-MorpheusDnsRecord @Params
        '''
        // Prepare parameters to replace in the command template
        def computer = computerName ?: ""
        def createPtr = createPtrRecord ? '$True' : '$False'
        def ttlString = ttl ? ttl.toString() : "3600"
        def userScript = userCmd.stripIndent()
            .replace("<%rrtype%>",rrType)
            .replace("<%name%>",name)
            .replace("<%zone%>",zone)
            .replace("<%data%>",recordData)
            .replace("<%ttl%>",ttlString)
            .replace("<%createptr%>",createPtr)
            .replace("<%computer%>",computer)
            .replace("<%servicetype%>",serviceType)
        // Load Template and add the userScript
        runCmd = template.replace("<%usercode%>",userScript)
        log.info("buildAddDRecordScript - Building script to add ${rrType} record - host: ${name}, zone: ${zone}, recordData: ${recordData}, ttl : ${ttlString}, createPtr: ${createPtrRecord ? 'True' : 'False'}")        
        log.debug("buildAddDRecordScript : ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Removing a Dns Resource record
     * Specify the Resource Record to be Deleted (rrType). Supported options can be clearly seen in the switch statement
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildRemoveDnsServerRecordScript(String rrType, String name, String zone, String recordData, String computerName, String serviceType) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def userCmd = '''
        #
        $Params = @{
            RrType="<%rrtype%>";
            Name="<%name%>";
            Zone="<%zone%>";
            Data="<%data%>";
            Computer="<%computer%>";
            ServiceType="<%servicetype%>"
        }        
        $rtn=Remove-MorpheusDnsRecord @Params
        '''
        // Prepare parameters to replace in the command template
        def computer = computerName ?: ""
        def userScript = userCmd.stripIndent()
            .replace("<%rrtype%>",rrType)
            .replace("<%name%>",name)
            .replace("<%zone%>",zone)
            .replace("<%data%>",recordData)
            .replace("<%computer%>",computer)
            .replace("<%servicetype%>",serviceType)
        runCmd = template.replace("<%usercode%>",userScript)
        log.info("buildRemoveDnsServerRecordScript - Building script to remove ${rrType} record - host: ${name}, zone: ${zone}, recordData: ${recordData}")
        log.debug("buildRemoveDnsServerRecordScript : ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Retrieving DNS Zones
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     *
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildGetDnsZoneScript(String computerName, String serviceType) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def userCmd = '''
        #
        $Params = @{
            Computer="<%computer%>";
            ServiceType="<%servicetype%>"
        } 
        $rtn=Get-MorpheusDnsZone @Params
        '''
        // Prepare parameters to replace in the command template
        def computer = computerName ?: ""
        def userScript = userCmd.stripIndent()
            .replace("<%computer%>",computer)
            .replace("<%servicetype%>",serviceType)
        runCmd = template.replace("<%usercode%>",userScript)
        log.info("buildGetDnsZoneScript - Building script to Zone records")
        log.debug("buildGetDnsZoneScript : ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Retrieving DNS Zones Records
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     *
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildGetDnsResourceRecordScript(String zone, String computerName, String serviceType) {
        String runCmd
        def template = MicrosoftDnsPluginHelper.templateHelperScript()
        def userCmd = '''
        #
        $Params = @{
            Zone="<%zone%>";
            Computer="<%computer%>";
            ServiceType="<%servicetype%>"
        }         
        $rtn=Get-MorpheusDnsResourceRecord @Params
        '''
        // Prepare parameters to replace in the command template
        def computer = computerName ?: ""
        def userScript = userCmd.stripIndent()
            .replace("<%zone%>",zone)
            .replace("<%computer%>",computer)
            .replace("<%servicetype%>",serviceType)
        runCmd = template.replace("<%usercode%>",userScript)
        log.info("buildGetDnsResourceRecordScript - Building script to get zone resource records for zone ${zone}")
        log.debug("buildGetDnsResourceRecordScript : ${runCmd}")
        return runCmd
    }
 
}
