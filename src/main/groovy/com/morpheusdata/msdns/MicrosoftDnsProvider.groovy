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
import com.morpheusdata.core.util.NetworkUtility
import com.morpheusdata.core.util.SyncTask
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.model.Icon
import com.morpheusdata.model.NetworkDomain
import com.morpheusdata.model.NetworkDomainRecord
import com.morpheusdata.model.OptionType
import com.morpheusdata.model.projection.NetworkDomainIdentityProjection
import com.morpheusdata.model.projection.NetworkDomainRecordIdentityProjection
import com.morpheusdata.response.ServiceResponse
import groovy.util.logging.Slf4j
import io.reactivex.rxjava3.core.Single
import io.reactivex.rxjava3.core.Observable
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
    MicrosoftDnsPluginRpcService rpcService
    static DEFAULT_TTL = 3600

    MicrosoftDnsProvider(Plugin plugin, MorpheusContext morpheusContext) {
        log.info("MicrosoftDnsProvider: Constructor called")
        this.morpheusContext = morpheusContext
        this.plugin = plugin
        this.rpcService = new MicrosoftDnsPluginRpcService(morpheusContext)
    }

    /**
     * Gets the rpc and service profile for AccountIntegration id
     * 
     * Useful for troubleshooting the connection to DNS
    */
    ServiceResponse getIntegrationServiceProfile(Long integrationId) {
        try {
            //AccountIntegration integration = morpheusContext.getAccountIntegration().get(integrationId).blockingGet()
            AccountIntegration integration = getMorpheus().getAsync().getAccountIntegration().get(integrationId).blockingGet()
            if (integration?.type == "microsoft.dns") {
                log.info("getIntegrationServiceProfile - Getting Service Profile for ${integration.name}")
                if (!integration?.credentialLoaded) {
                    //No credentials loaded. Load via credentialService
                    def credentialService = getMorpheus().getServices().getAccountCredential()
                    def cred = credentialService.loadCredentials(integration).getData()
                    log.info("getIntegrationServiceProfil - Integration: Loading Credential Data via service ${cred}")
                    integration.setCredentialData(cred)
                    integration.setCredentialLoaded(true)
                }
                return testDnsServiceProfile(integration)
            } else {
                return ServiceResponse.error("AccountIntegration with id ${integrationId} is not a valid Microsoft DNS Integration")
            }
        }
        catch (e) {
            log.error("getIntegrationServiceProfile - Error accessing service profile for integration with id ${integrationId} - ${e.getMessage()}")
            return ServiceResponse.error("Failed to load AccountIntegration with id ${integrationId}")
        }
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
        if (!validateRecord.success) {
            // Failed validation
            return validateRecord
        }
        ServiceResponse rpcResult
        ServiceResponse<NetworkDomainRecord> addResult = ServiceResponse.prepare()
        def config = integration.getConfigMap()
        String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
        String serviceType = config?.serviceType
        Boolean createPtrRecord = (integration.serviceFlag == null) ? false : integration.serviceFlag
        String zone = record.networkDomain?.name // DNS Zone
        try {
            String command = MicrosoftDnsPluginHelper.buildAddDnsRecordScript(record.type, record.name, zone, record.content, record.ttl, createPtrRecord, computerName, serviceType)
            rpcResult = rpcService.executeCommand(command, integration)
        }
        catch (e) {
            log.error("createRecord - integration ${integration.name} raised exception error: ${e.getMessage()}")
            return ServiceResponse.error("Failed to create DNS record via Integration ${integration.name} - exception ${e.getMessage()}")
        }
        if (rpcResult.success) {
            //rpc process has returned a successful response - process the record
            def rpcData = rpcResult.getData()
            //got response from DNS
            log.info("createRecord - integration ${integration.name} : returned rpcData : ${rpcData}")
            def returnedDnsRecords = rpcData.cmdOut
            log.debug("createRecord - Rpc Process returned matching newDnsRecords : ${returnedDnsRecords}")
            def newDnsRecord = returnedDnsRecords.find { (it.recordData.startsWithIgnoreCase(record.content)) }
            if (newDnsRecord) {
                log.info("createRecord - integration ${integration.name} : rpcData returned new record ${newDnsRecord}")
                //Update Morpheus record data from the confirmed response returned from DNS
                record.name = newDnsRecord.hostName
                record.internalId = newDnsRecord.recordData
                record.externalId = newDnsRecord.distinguishedName
                record.content = newDnsRecord.recordData
                record.recordData = newDnsRecord.recordData
                log.info("createRecord - integration ${integration.name} - Successfully created ${record.type} record - host: ${record.name}, zone: ${zone}, data: ${record.recordData}")
                addResult.setSuccess(true)
                addResult.setMsg("Successfully created ${record.type} record ${record.name} in zone ${zone} data ${record.recordData}")
                addResult.setData(record)
            } else {
                addResult.setSuccess(false)
                addResult.addError("Failed to verify that the record was created via the DNS Services")
                addResult.setData(record)
            }
        } else {
            log.error("createRecord - integration ${integration.name} - rpc process failed to create DNS record")
            addResult.setSuccess(false)
            addResult.addError("Integration ${integration.name} - failed to Create DNS record: host: ${record.name}, zone: ${zone}, data: ${record.recordData}")
            addResult.setData(record)
        }
        return addResult
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
        ServiceResponse rpcResult
        ServiceResponse<NetworkDomainRecord> deleteResult = ServiceResponse.prepare()
        def config = integration.getConfigMap()
        String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
        String serviceType = config?.serviceType
        String rrType = record.type
        String fqdn = record.fqdn
        String name = record.name
        String recordData = record.recordData
        String zone = record.networkDomain.name
        try {
            String command = MicrosoftDnsPluginHelper.buildRemoveDnsServerRecordScript(rrType,name,zone,recordData,computerName,serviceType)
            rpcResult = rpcService.executeCommand(command, integration)
        }
        catch (e) {
            log.error("createRecord - integration ${integration.name} raised exception error: ${e.getMessage()}")
            return ServiceResponse.error("Failed to create DNS record via Integration ${integration.name} - exception ${e.getMessage()}")
        }
        if (rpcResult.success) {
            def rpcData = rpcResult.getData()
            if (rpcData) {
                log.info("deleteRecord - integration ${integration.name} : rpcData : ${rpcData}")
                switch (rpcData.status) {
                    case 9714 :
                        //9714 DNS Record does not Exist - return success response to have Morpheus delete its copy
                        deleteResult.success = true
                        deleteResult.msg = rpcData.errOut?.message
                        log.warn("deleteRecord - integration ${integration.name} - Record does not exist in DNS - removing Morpheus copy")
                        break
                    case 0 :
                        deleteResult.success = true
                        deleteResult.msg = "Successfully removed ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}"
                        log.info("deleteRecord - integration: ${integration.name} - Successfully removed ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}")
                        break
                    default :
                        deleteResult.success = false
                        deleteResult.addError(rpcData.errOut?.message)
                        log.error("deleteRecord - integration: ${integration.name} - Error removing ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData} - errOut: ${rpcData.errOut}")
                        break
                }
            } else {
                log.error("deleteRecord - integration: ${integration.name} - Unable to determine rpcData from Dns Services")
                deleteResult.success = false
                deleteResult.addError("Unable to determine rpcData returned from Dns Services")
            }
            return deleteResult
        } else {
            //rpc call failed use ServiceResponse from rpc call to report error
            return rpcResult
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
            Map integrationConfig = integration.getConfigMap()
            // Are we using Agent or winRm for transport
            String rpcTransport = (integrationConfig?.agentRpc && integrationConfig?.agentRpc == "on") ? "agent" : "winrm"
            Boolean importZoneRecords = (integrationConfig?.inventoryExisting && integrationConfig?.inventoryExisting == "on")
            ServiceResponse rpcTest = testRpcConnection(integration)
            log.info("refresh - integration ${integration.name} - checking the integration is online - ${integration.serviceUrl} - ${rpcTest.success}")
            if(rpcTest.success) {
                ServiceResponse testDns = testDnsService(integration)
                if (testDns.success) {
                    Date now = new Date()
                    cacheZones(integration)
                    if (importZoneRecords) {
                        log.info("refresh - integration: ${integration.name} - Importing existing Resource Records matching Zone filter")
                        cacheZoneRecords(integration)
                    } else {
                        log.info("refresh - integration: ${integration.name} - This integration will not import existing DNS Resource Records")
                    }
                    log.info("refresh - integration: ${integration.name} - Sync Completed in ${new Date().time - now.time}ms")
                    getMorpheus().getAsync().getIntegration().updateAccountIntegrationStatus(integration, AccountIntegration.Status.ok).subscribe().dispose()
                    //getMorpheus().getIntegration().updateAccountIntegrationStatus(integration, AccountIntegration.Status.ok).subscribe().dispose()
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
        ServiceResponse<AccountIntegration> verify = ServiceResponse.prepare(integration)
        Map config = integration.getConfigMap()
        // config.zoneFilter is the glob style filter for importing zones
        // config.serviceType - how to access DNS Service. One of "local", "winrm" or "wmi"
        // config.agentRpc - Use a Morpheus Agent configured with a service account for the rpc transport
        String rpcTransport = (config?.agentRpc && config?.agentRpc == "on") ? "agent" : "winrm"
        //def credentialService = morpheusContext.getAccountCredential()
        log.debug("verifyAccountIntegration - Validating integration: ${integration.getProperties()} - opts: ${opts}")
        log.info("verifyAccountIntegration - integration: ${integration.name} - serviceUrl: ${integration.serviceUrl}, servicePath: ${integration.servicePath}, config: ${config}")
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
            if (integration.servicePath) {
                if (["winrm","wmi"].find {it == config.serviceType?.toLowerCase()} == null) {
                    verify.errors["serviceType"] = "Service type must be wmi or winrm"
                }
            } else {
                // serviceType MUST be local
                integration.setConfigProperty("serviceType","local")
            }
            if (verify.errors.size() > 0) {
                // Errors on form - return these errors now
                log.error("verifyAccountIntegration - integration: ${integration.name}. Form validation errors while Adding Integration: ${verify.errors}")
                verify.success = false
                return verify
            }
            // Validate connectivity to serviceUrl over WinRM if rpcType is winrm - return immediately on a fail
            if (rpcTransport == "winrm") {
                String port = integration.servicePort ?: "5985"
                log.info("verifyAccountIntegration - integration: ${integration.name} - Transport ${rpcTransport} port ${port}")
                def serviceHostOnline = ConnectionUtils.testHostConnectivity(integration.serviceUrl, port.toInteger(), false, true, null)
                if (!serviceHostOnline) {
                    log.warn("verifyAccountIntegration - integration: ${integration.name} - no winRm connectivity to serviceUrl: ${integration.serviceUrl}")
                    verify.errors["serviceUrl"] = "serviceUrl ${integration.serviceUrl} not reachable over WinRM (port ${port})"
                    verify.success = false
                    return verify
                }
            } else {
                log.info("verifyAccountIntegration - integration: ${integration.name} - Using Morpheus agent as Rpc Transport")
            }
            //Quickly test the rpcProcess before conducting a more thorough test of DNS Services
            ServiceResponse rpcTest = testRpcConnection(integration)
            log.info("verifyAccountIntegration - integration: ${integration.name} : $rpcTest.data")
            if (!rpcTest.success) {
                verify.errors["serviceUrl"] = "the rpc connection to ${integration.serviceUrl} using ${rpcTransport} has failed. Check Credentials and/or Agent status"
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
            log.error("verifyAccountIntegration - Integration: ${integration.name} : Raised Exception ${e.getMessage()}")
            verify.success = false
            verify.addError(e.getMessage() ?: "Unknown exception raised in verifyAccountIntegration")
            return verify
        }
    }

    /**
     * syncs in the Zone records collected bu the rpcService.
     * NOTE that the json Data returned by the ServiceResponse now has camel case property names
     * @param integration
     * @param opts
     */
    def cacheZones(AccountIntegration integration, Map opts = [:]) {
        try {
            ServiceResponse listResults = listZones(integration)
            if (listResults.success) {
                List apiItems = listResults.getData() as List<Map>
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
     * NOTE that the json Data returned by the ServiceResponse now has camel case property names
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
            log.debug("Adding Zone: ${networkDomain}")
            return networkDomain
        }
        getMorpheus().getAsync().getNetwork().getDomain().create(integration.id,missingZonesList).blockingGet()
        // deprecated morpheus.network.domain.create(integration.id, missingZonesList).blockingGet()
    }

    /**
     * Given an AccountIntegration (integration) and updateList, update NetwordDomain zone records
     * @param integration
     * @param updateList
     */
    void updateMatchedZones(AccountIntegration integration, List<SyncTask.UpdateItem<NetworkDomain,Map>> updateList) {
        List<NetworkDomain> domainsToUpdate = []
        log.debug("updateMatchedZones -  update Zones for ${integration.name} - updated items ${updateList.size()}")
        for(SyncTask.UpdateItem<NetworkDomain,Map> update in updateList) {
            NetworkDomain existingItem = update.existingItem
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
                    log.debug("updateMatchedZones -  ready to update item ${existingItem}")
                    domainsToUpdate.add(existingItem)
                }
            }
        }
        if(domainsToUpdate.size() > 0) {
            getMorpheus().getAsync().getNetwork().getDomain().bulkSave(domainsToUpdate).blockingGet()
            // morpheus.network.domain.save(domainsToUpdate).blockingGet()
        }
    }


    // Cache Zones methods
    def cacheZoneRecords(AccountIntegration integration, Map opts=[:]) {
        //Use new Async service
        getMorpheus().getAsync().getNetwork().getDomain().listIdentityProjections(integration.id).buffer(50).concatMap { Collection<NetworkDomainIdentityProjection> resourceIdents ->
            return getMorpheus().getAsync().getNetwork().getDomain().listById(resourceIdents.collect{it.id})
        }.flatMap { NetworkDomain domain ->
            ServiceResponse listResults = listRecords(integration,domain)

            log.debug("cacheZoneRecords - domain: ${domain.externalId}, listResults: ${listResults}")
            if (listResults.success) {
                List<Map> apiItems = listResults.getData() as List<Map>
                //Unfortunately the unique identification matching for msdns requires the full record for now... so we have to load all records...this should be fixed

                Observable<NetworkDomainRecord> domainRecords = getMorpheus().getNetwork().getDomain().getRecord().listIdentityProjections(domain,null).buffer(50).flatMap {domainIdentities ->
                    getMorpheus().getAsync().getNetwork().getDomain().getRecord().listById(domainIdentities.collect{it.id})
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
                    return getMorpheus().getAsync().getNetwork().getDomain().getRecord().listById(updateItems.collect{it.existingItem.id} as Collection<Long>).map { NetworkDomainRecord domainRecord ->
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
        List<NetworkDomainRecord> records = []
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
            getMorpheus().getAsync().getNetwork().getDomain().getRecord().bulkSave(records).blockingGet()
        }
    }

    void addMissingDomainRecords(NetworkDomain domain, Collection<Map> addList) {
        List<NetworkDomainRecord> records = []
        addList?.each {record ->
            if(record['hostName']) {
                def addConfig = [networkDomain:new NetworkDomain(id: domain.id), fqdn:NetworkUtility.getDomainRecordFqdn(record['hostName'] as String, domain.fqdn),
                                 type:record['recordType']?.toUpperCase(), comments:record.comments, ttl:record['timeToLive'],
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
        //deprecated orpheus.network.domain.record.create(domain,records).blockingGet()
        getMorpheus().getAsync().getNetwork().getDomain().getRecord().create(domain,records).blockingGet()
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
                    helpText: 'Name of the server hosting the Morpheus Rpc connection. May also be the DNS Server',
                    displayOrder: 0
                ),
                new OptionType(
                        code: 'accountIntegration.microsoft.dns.servicePort',
                        name: 'Rpc Port',
                        inputType: OptionType.InputType.TEXT,
                        fieldName: 'servicePort',
                        fieldLabel: 'Rpc Port',
                        fieldContext: 'domain',
                        required: false,
                        defaultValue: '5985',
                        displayOrder: 2,
                        visibleOnCode: 'accountIntegration.microsoft.dns.agentRpc:off',
                        helpBlock: 'winRm Rpc service port number (5985/5986)'
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.agentRpc',
                    name: 'agentRpc',
                    inputType: OptionType.InputType.CHECKBOX,
                    category:'accountIntegration.microsoft.dns',
                    fieldName:'agentRpc',
                    fieldLabel:'Use Agent for Rpc',
                    fieldContext:'config',
                    required:false,
                    enabled:true,
                    editable:true,
                    global:false,
                    placeHolder:null,
                    helpBlock:'Use Morpheus agent for Rpc transport, Agent should LogOn as Service Account',
                    defaultValue:'off',
                    custom:false,
                    displayOrder:5
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.credentials', 
                    name: 'Credentials', 
                    inputType: OptionType.InputType.CREDENTIAL, 
                    fieldName: 'type', 
                    fieldLabel: 'Credentials', 
                    fieldContext: 'credential', 
                    required: true, 
                    displayOrder: 10,
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
                    displayOrder: 11,
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
                    displayOrder: 12,
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
                    displayOrder:20
                ),
                new OptionType(
                    code:'accountIntegration.microsoft.dns.serviceType',
                    inputType: OptionType.InputType.SELECT,
                    name:'serviceType',
                    category:'accountIntegration.microsoft.dns',
                    fieldName:'serviceType',
                    fieldLabel:'Service Type',
                    fieldContext:'config',
                    required: false,
                    optionSource:'msdnsServiceTypeList',
                    helpBlock:'How Rpc Server should access DNS Services on the DNS Server',
                    visibleOnCode: 'accountIntegration.microsoft.dns.servicePath:^.+$',
                    displayOrder:30,
                    defaultValue:'local'
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
                    helpBlock:'Have DNS automatically attempt to create a PTR record with the forward record',
                    defaultValue:'on',
                    displayOrder:80
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.zoneFilter', 
                    name: 'Zone Filter', 
                    inputType: OptionType.InputType.TEXT, 
                    fieldName: 'zoneFilter', 
                    fieldLabel: 'Zone Filter', 
                    required: false,
                    helpText: 'Comma separated string of glob style zone names to import. All zones are imported if left blank',
                    fieldContext:'config',
                    displayOrder: 40
                ),
                new OptionType(
                    code: 'accountIntegration.microsoft.dns.inventoryExisting',
                    name: 'Inventory Existing',
                    inputType: OptionType.InputType.CHECKBOX,
                    defaultValue: 'off',
                    fieldName: 'inventoryExisting',
                    fieldLabel:' Inventory Existing',
                    fieldContext: 'config',
                    required: false,
                    enabled:true,
                    editable:true,
                    helpBlock:'Import existing Resource Records from imported Zones. Not recommended in large environments',
                    displayOrder:50
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

    /**
     * Discovers the Dns Zones for this integration
     *
     * @param AccountIntegration integration
     * @return ServiceResponse with list of discovered Zones
     */
    ServiceResponse listZones(AccountIntegration integration) {
        ServiceResponse rpcCall
        ServiceResponse collector
        def zoneFilters //holds an array of RegEx patterns. Zones matching any filter will be imported
        def config = integration.getConfigMap()
        zoneFilters = config.zoneFilter ? config.zoneFilter.tokenize(",").collect { makeZoneFilterRegex(it) } : null

        try {
            String serviceType = config.serviceType
            rpcCall = rpcService.executeCommand(MicrosoftDnsPluginHelper.buildGetDnsZoneScript(integration.servicePath, serviceType), integration)
        }
        catch (e) {
            log.error("listZones  - integration ${integration.name} raised exception error: ${e.getMessage()}")
            return ServiceResponse.error("Failed to get the list of Zones from integration ${integration.name}")
        }
        if (rpcCall.success) {
            List<Map> zoneRecords = rpcCall.getData()?.cmdOut
            log.debug("listZones - integration ${integration.name} - zoneRecords: ${zoneRecords}")
            if (zoneFilters) {
                log.info("listZones - integration ${integration.name} - Applying glob style zone filters : ${config.zoneFilter} regEx: ${zoneFilters}")
                List<Map> filteredZoneRecords = zoneRecords.collect { zone ->
                    // Does this zone name match any of the import zoneFilters
                    if (zoneFilters.find { (zone.zoneName ==~ it) }) {
                        log.info("listZones - integration ${integration.name} - found matching zone: {$zone.zoneName}")
                        return zone
                    } else {
                        log.warn("listZones - integration ${integration.name} - Skipping non-matching zone: {$zone.zoneName}")
                    }
                }.findAll()
                //Return the ServiceResponse with filtered zone records
                collector = ServiceResponse.prepare(filteredZoneRecords)
                collector.setSuccess(true)
                collector.setMsg("Importing zones with matching Zone Filter ${config.zoneFilter}")
                return collector
            } else {
                collector = ServiceResponse.prepare(zoneRecords)
                collector.setSuccess(true)
                collector.setMsg("Importing all discovered Zone records")
                log.info("listZones - integration ${integration.name} - No Zone filter - importing all zones")
                return collector
            }
        } else {
            log.error("listZones - integration ${integration.name} - Failed to get Dns Zone list")
            return ServiceResponse.error("integration ${integration.name} - Unable to collect Zone records")
        }
    }

    /**
     * Use the rpcService to return q list of Zone Resource records
     *
     * @param AccountIntegration integration
     * @return ServiceResponse containing the List<Map> of zoneRecords
     */
    ServiceResponse listRecords(AccountIntegration integration, NetworkDomain domain) {
        ServiceResponse rpcCall
        ServiceResponse collector
        try {
            log.info("listRecords - integration ${integration.name} - importing zone ${domain.externalId}")
            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String serviceType = integration.getConfigProperty("serviceType")
            rpcCall = rpcService.executeCommand(MicrosoftDnsPluginHelper.buildGetDnsResourceRecordScript(domain.externalId, computerName, serviceType), integration)
        }
        catch (e) {
            log.error("listRecords  - integration ${integration.name} raised exception error: ${e.getMessage()}")
            return ServiceResponse.error("Failed to get the list of Zone Records from integration ${integration.name}")
        }
        if (rpcCall.success) {
            List<Map> zoneRecords = rpcCall.getData()?.cmdOut
            collector = ServiceResponse.prepare(zoneRecords)
            collector.setSuccess(true)
            collector.setMsg("zone: ${domain.externalId} resourceRecords: ${zoneRecords.size()}")
            log.info("listRecords - integration ${integration.name} - zone: ${domain.externalId} resourceRecords: ${zoneRecords.size()}")
            return collector
        } else {
            log.warn("listRecords - integration ${integration.name} - Unable to collect records for zone: ${domain.externalId}")
            return ServiceResponse.error("integration ${integration.name} - Unable to collect records for zone: ${domain.externalId}")
        }
    }

    /**
     * Using the properties selected in the Edit Integration dialog, test access to DNS Service
     * A Service Profile defines
     * rpcType (winrm or agent)
     * serviceHost (the DNS Server if not local)
     * serviceType (wmi or winrm if remote otherwise local)
     * @param integration
     * @return  ServiceResponse
     */
    ServiceResponse testDnsServiceProfile(AccountIntegration integration) {

        String serviceType = integration.getConfigProperty("serviceType")
        String command
        try {
            log.info("testDnsServiceProfile - integration ${integration.name} - Testing access to DNS services using serviceType ${serviceType}")
            command = MicrosoftDnsPluginHelper.buildTestDnsServiceScript(integration.servicePath, serviceType)
            return rpcService.executeCommand(command,integration)
        }
        catch(e) {
            log.error("testDnsServiceProfile - integration ${integration.name} raised exception: ${e.getMessage()}")
            return ServiceResponse.error("Exception raised discovering service profile ${e.getMessage()}")
        }
    }

    /**
     * Validates the Dns Resource Record
     * returns ServiceResponse
     * @paramNetworkDomainRecord record
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
                case "AAAA" :
                    if (!(NetworkUtility.validateIpAddr(record.content,true))) {
                        ret.success = false
                        ret.addError("content","IP v6 Address ${record?.content} is not valid")
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
    private static Boolean supportedRrType(String rrType) {
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
    private static String getNQDN(String hostName, String zoneName) {
         
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
                return Pattern.compile(regexFilter,Pattern.CASE_INSENSITIVE)
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
     * @param AccountIntegration integration
     */
    ServiceResponse verifyMorpheusDnsPluginPowershell(AccountIntegration integration) {
        String runCmd
        ServiceResponse rpcCall

        log.debug("verifyMorpheusDnsPluginPowershell - integration ${integration.name} - checking Morpheus Helper module ${MicrosoftDnsPluginHelper.getHelperFile()} on ${integration.serviceUrl}")
        rpcCall = rpcService.executeCommand(MicrosoftDnsPluginHelper.testHelperFileScript(), integration)
        //log.info("verifyMorpheusDnsPluginPowershell TESTING ${rpcCall.dump()}")
        if (rpcCall.success) {
            return rpcCall
        } else {
            if (rpcCall.data?.status == 9) {
                log.warn("verifyMorpheusDnsPluginPowershell - integration ${integration.name} - ${rpcCall.data?.errOut}")
                ServiceResponse xferRpc = transferDnsHelperScript(integration)
                if (xferRpc.success) {
                    log.info("verifyMorpheusDnsPluginPowershell - integration ${integration.name} - Successfully transferred Morpheus Helper module - re-running tests")
                    return rpcService.executeCommand(MicrosoftDnsPluginHelper.testHelperFileScript(), integration)
                } else {
                    log.error("verifyMorpheusDnsPluginPowershell - integration ${integration.name} - Failed to transfer Morpheus Helper module")
                    return xferRpc
                }
            } else {
                log.error("verifyMorpheusDnsPluginPowershell - integration ${integration.name} - Error verifying Morpheus Helper module ${rpcCall.data.errOut}")
                return rpcCall
            }
        }
    }

    /**
     * This method transfers a Powershell script file containing the Functions needed to support this Integration into the %LOCALAPPDATA
     * path in the Service Account user profile. It helps to overcome the size limitations imposed by the Rpc service
     */       
    private ServiceResponse transferDnsHelperScript(AccountIntegration integration) {
        String runCmd
        String contentToXfer = MicrosoftDnsPluginHelper.morpheusDnsHelperScript()

        ServiceResponse rtn
        log.info("transferDnsHelperScript - integration ${integration.name} - Preparing to transfer helper script in 1k fragments")
        try {
            def i = 0
            while(contentToXfer) {
                log.debug("transferDnsHelperScript - integration ${integration.name} - transferring helper script fragment ${i} ...")
                def chunk = contentToXfer.take(1024)
                contentToXfer = contentToXfer.drop(1024)
                def b64Block = chunk.getBytes("UTF-8").encodeBase64().toString()
                runCmd = MicrosoftDnsPluginHelper.copyHelperBlockScript(b64Block)
                rtn = rpcService.executeCommand(runCmd,integration)
                if(!rtn.success) {
                    log.warn("transferDnsHelperScript - integration ${integration.name} - Failed to transfer helper script - ${rtn.errOut}")
                    break
                }
                i = i+1
            }
            log.info("transferDnsHelperScript - integration ${integration.name} - Transfer complete")
            return rtn
        }
        catch (e) {
            log.error("transferDnsHelperScript - integration ${integration.name} - Exception ${e.getMessage()}")
            if (rtn) {
                return rtn
            } else {
                return ServiceResponse.error("Failed to transfer helper module. Exception ${e.getMessage()}")
            }
        }
    }

    /**
     * Tests the integration rpc service configuration (agent or winrm) hosted on the serviceUrl using the credentials
     * provided on the integration dialog.
     * Returns a ServiceResponse
     */
    ServiceResponse testRpcConnection(AccountIntegration integration) {
        return rpcService.executeCommand(MicrosoftDnsPluginHelper.testRpcConnection(),integration)
    }


    /**
     * Tests if the integration can access the DNS Services with the credentials provided either
     * directly (serviceUrl) or via an intermediate server (servicePath).
     * A lock is used to protect the helper script transfer to the serviceUrl
     * tests comprise these steps
     *   verify the Morpheus Powershell Helper Module is installed and has a valid chksum
     *   update cached credentials if using an intermediate server
     *   test access to DNS Services
     * Returns a ServiceResponse
     */
    ServiceResponse testDnsService(AccountIntegration integration) {
        String command
        def rpcData
        def config = integration.getConfigMap()
        String computerName = integration.servicePath ?: ""
        String serviceType = config.serviceType
        // Prepare the return ServiceResponse
        ServiceResponse<AccountIntegration> serviceTest = ServiceResponse.prepare(integration)
        String lockName = "${getCode()}.helper.${integration.serviceUrl}.${MicrosoftDnsPluginHelper.getHelperFile()}"
        String lockId
        ServiceResponse rpcCall
        ServiceResponse testHelper
        ServiceResponse testDnsProfile
        try {
            // Step 1: Veryify and if needed transfer Morpheus Helper Module
            log.info("testDnsService - integration: ${integration.name} - Checking Morpheus Helper Powershell script is valid on rpcHost ${integration.serviceUrl}")
            log.info("testDnsService - integration: ${integration.name} - attempting to grab lock ${lockName} ...")
            lockId = morpheusContext.acquireLock(lockName, [ttl: 120000L, timeout: 60000L]).blockingGet()
            log.info("testDnsService - integration: ${integration.name} - Acquired lock: ${lockName}, value: ${lockId}")
            testHelper = verifyMorpheusDnsPluginPowershell(integration)
            log.info("TESTING ${testHelper.dump()}")

        }
        catch (e) {
            log.error("testDnsService - integration: ${integration.name} - Unable to verify DNS Helper Script - Possibly locked by another integration.")
            //return ServiceResponse.error("Unable to verify DNS Helper at this time. Possible locked by another integration")
        }
        finally {
            if (lockId) {
                log.info("testDnsService - integration: ${integration.name} - Releasing lock: ${lockName}, value: ${lockId}")
                morpheusContext.releaseLock(lockName, [lock: lockId]).blockingGet()
            }
        }
        if (testHelper && testHelper.success) {
            log.info("testDnsService - integration: ${integration.name} - Morpheus Powershell Module verified with checksum ${testHelper.getData().cmdOut?.md5Chksum}")
        } else {
            log.error("testDnsService - integration: ${integration.name} - Failed to transfer Morpheus Powershell Module - check account Credentials - ${testHelper}")
            serviceTest.success = false
            serviceTest.addError("serviceUrl","Failed to transfer Morpheus Powershell Helper Module - check account Credentials for ${integration.serviceUrl}")
            return serviceTest
        }
        //Step 2: Cache credential in case its needed to upgrade the NTLM connection
        try {
            //Cache Credentials if using an intermediate server
            log.info("testDnsService - integration: ${integration.name} - Caching credential on host ${integration.serviceUrl}")
            String username = integration.credentialData?.username ?: integration.serviceUsername
            String password = integration.credentialData?.password ?: integration.servicePassword
            command = MicrosoftDnsPluginHelper.buildCacheCredentialScript(username, password)
            rpcCall = rpcService.executeCommand(command, integration)
            if (!rpcCall.success) {
                log.error("testDnsService - integration: ${integration.name} - Failed to securely cache credentials")
                return rpcCall
            } else {
                log.info("testDnsService - integration: ${integration.name} - Credentials securely cached on host ${integration.serviceUrl}")
            }
        }
        catch (e) {
            log.warn("testDnsService - integration: ${integration.name} Exception caching credentials on ${integration.servicePath} - ${e.getMessage()}")
            serviceTest.success = false
            serviceTest.addError("serviceUrl","Failed to securely cache credentials - error: ${e.getMessage()}")
            return serviceTest
        }
        //Final Step - test access to DNS Service with the chosen service profile
        try {
            testDnsProfile = testDnsServiceProfile(integration)
            rpcData = testDnsProfile.getData()
            log.debug("testDnsProfile ServiceResponse: ${testDnsProfile.dump()}")
            if (testDnsProfile.success) {
                Map serviceProfile = rpcData.cmdOut?.serviceProfile
                log.info("testDnsService - integration: ${integration.name} : Successful connection: Service Profile: ${serviceProfile}")
                serviceTest.success = true
                serviceTest.msg = "Successfully connected to Microsoft DNS Services"
                return serviceTest
            } else {
                log.error("testDnsService - integration: ${integration.name} - Rpc process failed to contact Services ${rpcData?.errOut?.message}")
                def errType = integration.servicePath ? "servicePath" : "serviceUrl"
                serviceTest.addError(errType, "Cannot access DNS Services with the selected service Profile. Check credentials, rpc method and Service Type are correct. Error message : ${rpcData.errOut?.message}")
                serviceTest.msg = "Failed to access Dns Services - error: ${rpcData?.errOut?.message}"
                serviceTest.success = false
                return serviceTest
            }
        }
        catch (e) {
            log.warn("testDnsService - integration: ${integration.name} Exception while testing DNS Services - ${e.getMessage()}")
            serviceTest.success = false
            serviceTest.addError("serviceUrl","Exception raised testing DNS Services : ${e.getMessage()}")
            return serviceTest
        }

    }
}
