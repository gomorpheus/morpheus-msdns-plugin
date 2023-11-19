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
import com.morpheusdata.core.data.DataFilter
import com.morpheusdata.core.data.DataQuery
import com.morpheusdata.core.util.ConnectionUtils
import com.morpheusdata.core.util.HttpApiClient
import com.morpheusdata.core.util.NetworkUtility
import com.morpheusdata.core.util.SyncTask
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.model.Icon
import com.morpheusdata.model.NetworkDomain
import com.morpheusdata.model.NetworkDomainRecord
import com.morpheusdata.model.NetworkPool
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
 * @author David Estes
 */
@Slf4j
class MicrosoftDnsProvider implements DNSProvider {

    MorpheusContext morpheusContext
    Plugin plugin

    MicrosoftDnsProvider(Plugin plugin, MorpheusContext morpheusContext) {
        this.morpheusContext = morpheusContext
        this.plugin = plugin
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

        //gather and verify new record data
        Boolean createPtrRecord = false
        String rrType = record.type.trim().toUpperCase()
        String recordData = record.content  // Content - IpAddress or alias depends on rrType
        String zone = record.networkDomain?.name // zone where record is to be added
        String name = getNQDN(record.name,zone) // non qualified host name - will create record based on this
        String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
        // Create PTR at same time as A record if possible
        createPtrRecord = (integration.serviceFlag == null || integration.serviceFlag)
        // set a default ttl if null
        Integer ttl = record.ttl ?: 3600

        log.info("createRecord: Request to create resource record type: ${rrType} via Dns integration ${integration.name}")
        def recordCheck = validateDnsRecord(zone,name,rrType,recordData,ttl)
        if (recordCheck.isValid) {
            //record type is valid and a supported type go ahead and add
            try {     
                String command = buildAddDnsServerRecordScript(rrType,name,zone,recordData,ttl,createPtrRecord,computerName)
                def rpcData = executeCommandScript(integration, command)
                if (!rpcData) {
                    log.error("createRecord - integration ${integration.name} - Unable to determine rpcData from Dns Services")  
                    rtn.error("Unable to determine rpcData from Dns Services")
                    return new ServiceResponse<NetworkDomainRecord>(false,"Unable to determine rpcData from Dns Services",null,record)
                }
                if (rpcData.status == 0 ) {
                    //Rpc Process successful and response should be confirmation record was added. Use this to update the record
                    def getDnsRecords = parseListSet(rpcData.cmdOut)
                    log.debug("createRecord - Rpc Process returned matching newDnsRecords : ${getDnsRecords}")
                    //Could be multiple matching records - only take the one we added
                    def newDnsRecord = getDnsRecords.find {(it.RecordData.startsWithIgnoreCase(recordData))}
                    if (newDnsRecord) {
                        // update name and recordData from confirmed response - Note the Map returned by parseListSet is Pascal Case not the standard
                        name = newDnsRecord.HostName
                        recordData = newDnsRecord.RecordData
                        record.name = name
                        record.internalId = recordData
                        record.externalId = newDnsRecord.DistinguishedName
                        record.content = recordData
                        record.recordData = recordData
                        log.info("createRecord - integration ${integration.name} - Successfully created ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}")
                        return new ServiceResponse<NetworkDomainRecord>(true,"Successfully created ${rrType} record ${record.name} in zone ${zone} data ${recordData}",null,record)
                    } else {
                        log.warn("createRecord - integration ${integration.name} - Failed to confirm Resource Record was created as requested")
                        return new ServiceResponse<NetworkDomainRecord>(false,"Failed to confirm Resource Record was created as Requested",null,record)                        
                    }
                } else {
                    log.warn("createRecord - integration ${integration.name} - Failed to create Resource Record ${rpcData}")
                    return new ServiceResponse<NetworkDomainRecord>(false,rpcData.errOut.message,null,record)
                }
            } 
            catch(e) {
                log.error("createRecord - integration ${integration.name} Exception Raised : ${e.getMessgae()}")
            }
        } else {
            def failedItems = recordCheck.testedItems.findAll {(it.value == false)}
            log.error("createRecord - integration ${integration.name} new Dns Record failed validation")
            log.error("Resource Record ${record.getProperties()}. Validation failed for items ${failedItems}")
            return new ServiceResponse<NetworkDomainRecord>(false,"Error - Validation failed for the items ${failedItems}",null,record)
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
    
        try {
            String rrType = record.type
            String fqdn = record.fqdn
            String name = record.name
            String recordData = record.recordData
            String zone = record.networkDomain.name

            String computerName = integration.servicePath ?: "" // DnsServer if going via a service box
            String command = buildRemoveDnsServerRecordScript(rrType,name,zone,recordData,computerName)
            def rpcData = executeCommandScript(integration, command)
            if (!rpcData) {
                log.error("deleteRecord - integration: ${integration.name} - Unable to determine rpcData from Dns Services")
                return new ServiceResponse<NetworkDomainRecord>(false,"Unable to determine rpcData returned from Dns Services",null,record)
            }
            if (rpcData.status == 0 ) {
                log.info("deleteRecord - integration: ${integration.name} - Successfully removed ${rrType} record - host: ${name}, zone: ${zone}, data: ${recordData}")
                return new ServiceResponse<NetworkDomainRecord>(true,"Successfully removed ${rrType} record ${name} zone ${zone} data ${recordData}",null,record)
            } else {
                log.warn("deleteRecord - integration: ${integration.name} - Failed to delete Resource Record ${rpcData}")
                return new ServiceResponse<NetworkDomainRecord>(false,rpcData.errOut.message,null,record)
            }            
        } 
        catch(e) {
            log.error("deleteRecord - integration: ${integration.name} error: ${e}", e)
            return ServiceResponse.error("System Error removing Microsoft DNS Record ${record.name} - ${e.message}")
        }
    }


    /**
     * Periodically called to refresh and sync data coming from the relevant integration. Most integration providers
     * provide a method like this that is called periodically (typically 5 - 10 minutes). DNS Sync operates on a 10min
     * cycle by default. Useful for caching Host Records created outside of Morpheus.
     * @param poolServer The Integration Object contains all the saved information regarding configuration of the IPAM Provider.
     */
    @Override
    void refresh(AccountIntegration integration) {
        try {
            def rpcConfig = getRpcConfig(integration)
            def hostOnline = ConnectionUtils.testHostConnectivity(rpcConfig.host, rpcConfig.port ?: 5985, false, true, null)
            log.info("refresh - integration ${integration.name} - checking the integration is online - ${rpcConfig.host} - ${hostOnline}") 
            
            if(hostOnline) {
                Date now = new Date()
                cacheZones(integration)
                if(rpcConfig?.inventoryExisting) {
                    cacheZoneRecords(integration)
                }
                log.info("refresh - integration: ${integration.name} - Sync Completed in ${new Date().time - now.time}ms")
                morpheus.integration.updateAccountIntegrationStatus(integration, AccountIntegration.Status.ok).subscribe().dispose()
            } else {
                log.warn("refresh - integration: ${integration.name} - Integration appears to be offline")
                morpheus.integration.updateAccountIntegrationStatus(integration, AccountIntegration.Status.error, "Microsoft DNS integration ${integration.name} not reachable")
            }
        } catch(e) {
            log.error("refresh - Microsoft DNS error on integration ${integration.name}: ${e}")
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

        ServiceResponse rtn = new ServiceResponse()
        String computerName
        String command

        // config.zoneFilter is the glob style filter for importing zones
        def config = integration.getConfigMap()
        def rpcConfig = getRpcConfig(integration)
        //def credentialService = morpheusContext.getAccountCredential()
        log.info("verifyAccountIntegration - Validating integration: ${integration} - opts: ${opts}")
        try {
            // Validate Form options
            rtn.errors = [:]
            if(!rpcConfig.name || rpcConfig.name == ''){
                rtn.errors['name'] = 'Name is Required'
            }
            if(!rpcConfig.host || rpcConfig.host == ''){
                rtn.errors['serviceUrl'] = 'DNS Server is Required'
            }
            if(!rpcConfig.port || rpcConfig.port == ''){
                rtn.errors['servicePort'] = 'WinRM Port is Required'
            }
            if((!rpcConfig.password || rpcConfig.password == '')){
                rtn.errors['servicePassword'] = 'Password is Required'
            }
            if((!rpcConfig.username || rpcConfig.username == '')){
                rtn.errors['serviceUsername'] = 'Username is Required'
            }
            if (config.zoneFilter) {
                def zoneFilters = config.zoneFilter.tokenize(",").each {
                    if (!makeZoneFilterRegex(it)) {
                        rtn.errors["zoneFilter"] = "Invalid Zone Filter. Use comma separated list of zones to import in this format: *.mydomain.com, *.10.in-addr.arpa"
                    }
                }
            }

            // Validate Connectivity to serviceUrl over WinRM
            if (integration.serviceUrl) {
                log.info("verifyAccountIntegration - integration: ${integration.name} - checking winRm on serviceUrl: ${integration.serviceUrl}")
                def serviceHostOnline = ConnectionUtils.testHostConnectivity(rpcConfig.host, rpcConfig.port ?: 5985, false, true, null)
                if (!serviceHostOnline) {
                    log.warn("verifyAccountIntegration - integration: ${integration.name} - no winRm connectivity to serviceUrl: ${integration.serviceUrl} on port: ${rpcConfig.port}")
                    rtn.errors["serviceUrl"] = "serviceUrl not reachable over WinRM (port ${rpcConfig.port})"
                } else {
                    def rpcData
                    computerName = integration.servicePath ?: ""
                    def commandOpts = getRpcConfig(integration,computerName)
                    // If serviceUrl is a management server, servicePath is the actual DNS Server (-ComputerName parameter)
                    if (integration.servicePath) {
                        // Using a Management Server - save or update cached credentials
                        log.info("verifyAccountIntegration - integration: ${integration.name} - Securely caching credential on ${integration.serviceUrl} for onward use on ${integration.servicePath}")
                        command = buildCacheCredentialScript(commandOpts.username,commandOpts.password)
                        rpcData = executeCommandScript(integration,command)
                        if (rpcData?.status > 0) {
                            log.error("verifyAccountIntegration - integration: ${integration.name} - Failed to securely cache credentials ${rpcData?.errOut?.message}")
                            rtn.errors["servicePath"] = "Failed to securely cache credentials for use on ${computerName}"
                        }
                    }
                    // serviceUrl online: check for access via credentials
                    log.info("verifyAccountIntegration - integration: ${integration.name} - checking access to Dns Services via ${integration.serviceUrl}")
                    command = buildTestServiceCredentialScript(computerName)
                    rpcData = executeCommandScript(integration,command)
                    // rpcData.cmdOut contains properties about the user, group membership and DNS server version
                    log.info("verifyAccountIntegration - integration: ${integration.name} - Connection properties: ${rpcData}")
                    if (rpcData?.status > 0) {
                        log.error("verifyAccountIntegration - integration: ${integration.name} - Cannot access MicrosoftDns rpc Services ${rpcData.errOut.message}")
                        if (integration.servicePath) {
                            rtn.errors["servicePath"] = "Cannot access DNS Services with the cached Credentials provided"
                        } else {
                            rtn.errors["serviceUrl"] = "Cannot access DNS Services with the Credentials provided"
                        }
                    }
                }   
            }
            if(rtn.errors.size() > 0) {
                //Report Validation errors
                log.error("verifyAccountIntegration - integration: ${integration.name}. Form validation errors while Adding Integration: ${rtn.errors}")
                rtn.success = false
                return rtn
            }
            log.info("verifyAccountIntegration - Integration: ${integration.name} DNS Services validated OK")
            return ServiceResponse.success("DNS Integration validated OK")

        } catch(e) {
            log.error("validateService error: ${e}", e)
            return ServiceResponse.error(e.message ?: 'unknown error validating dns service')
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
                    domainObject.externalId == apiItem['ZoneName']
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
            networkDomain.externalId = zone['ZoneName']
            networkDomain.name = NetworkUtility.getFriendlyDomainName(zone['ZoneName'] as String)
            networkDomain.fqdn = NetworkUtility.getFqdnDomainName(zone['ZoneName'] as String)
            networkDomain.refSource = 'integration'
            networkDomain.zoneType = 'Authoritative'
            networkDomain.publicZone = true
            log.debug("Adding Zone: ${networkDomain}")
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
        log.debug("updateMatchedZones -  update Zones for ${integration.name} - updated items ${updateList.size()}")
        for(SyncTask.UpdateItem<NetworkDomain,Map> update in updateList) {
            NetworkDomain existingItem = update.existingItem as NetworkDomain
            if(existingItem) {
                Boolean save = false
                if(!existingItem.externalId) {
                    existingItem.externalId = update.masterItem['ZoneName']
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
            morpheus.network.domain.save(domainsToUpdate).blockingGet()
        }
    }


    // Cache Zones methods
    def cacheZoneRecords(AccountIntegration integration, Map opts=[:]) {

        morpheus.network.domain.list(new DataQuery().withFilters(new DataFilter('refType','AccountIntegration'),new DataFilter('refId',integration.id))).flatMap { NetworkDomain domain ->

            def now = new Date()
            def listResults = listRecords(integration,domain)
            log.info("List Zone Records in ${new Date().time - now.time}")

            if (listResults.success) {
                List<Map> apiItems = listResults.recordList as List<Map>

                //Unfortunately the unique identification matching for msdns requires the full record for now... so we have to load all records...this should be fixed

                Observable<NetworkDomainRecord> domainRecords = morpheus.network.domain.record.listIdentityProjections(domain,null).buffer(50).concatMap {domainIdentities ->
                    morpheus.network.domain.record.listById(domainIdentities.collect{it.id})
                }
                SyncTask<NetworkDomainRecord, Map, NetworkDomainRecord> syncTask = new SyncTask<NetworkDomainRecord, Map, NetworkDomainRecord>(domainRecords, apiItems)
                return syncTask.addMatchFunction {  NetworkDomainRecord domainObject, Map apiItem ->
                    (domainObject.externalId == apiItem['DistinguishedName'] && domainObject.internalId == apiItem['RecordData']) ||
                            (domainObject.externalId == null && domainObject.type == apiItem['RecordType']?.toUpperCase() && domainObject.fqdn == NetworkUtility.getDomainRecordFqdn(apiItem['HostName'] as String, domain.fqdn))

                }.onDelete {removeItems ->
                    morpheus.network.domain.record.remove(domain, removeItems).blockingGet()
                }.onAdd { itemsToAdd ->
                    addMissingDomainRecords(domain, itemsToAdd)
                }.withLoadObjectDetails { List<SyncTask.UpdateItemDto<NetworkDomainRecord,Map>> updateItems ->
                    return Observable.fromIterable(updateItems.collect { new SyncTask.UpdateItem<NetworkDomainRecord,Map>(existingItem: it.existingItem,masterItem: it.masterItem) })
                }.onUpdate { List<SyncTask.UpdateItem<NetworkDomainRecord,Map>> updateItems ->
                    updateMatchedDomainRecords(updateItems)
                }.observe()
            } else {
                log.info("cacheZoneRecords - No data to sync for ${domain.externalId}")
                return Single.just(false)
            }
        }.doOnError{ e ->
            log.error("cacheZoneRecords error: ${e}", e)
        }.blockingSubscribe()

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
                    existingItem.externalId = update.masterItem['DistinguishedName']
                    existingItem.internalId = update.masterItem['RecordData']
                    save = true
                }
                if(existingItem.content != update.masterItem['RecordData']) {
                    existingItem.content = update.masterItem['RecordData']
                    save = true
                }

                if(save) {
                    records.add(existingItem)
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
            if(record['HostName']) {
                def addConfig = [networkDomain:new NetworkDomain(id: domain.id), fqdn:NetworkUtility.getDomainRecordFqdn(record['HostName'] as String, domain.fqdn),
                                 type:record['RecordType']?.toUpperCase(), comments:record.comments, ttl:record['TimeToLive'],
                                 externalId:record['DistinguishedName'], internalId:record['RecordData'], source:'sync',
                                 recordData:record['RecordData'], content:record['RecordData']]
                if(addConfig.type == 'SOA' || addConfig.type == 'NS')
                    addConfig.name = record['HostName']
                else
                    addConfig.name = NetworkUtility.getFriendlyDomainName(record['HostName'] as String)
                def add = new NetworkDomainRecord(addConfig)
                records.add(add)
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
                new OptionType(code: 'accountIntegration.microsoft.dns.serviceUrl', name: 'Service URL', inputType: OptionType.InputType.TEXT, fieldName: 'serviceUrl', fieldLabel: 'DNS Server', fieldContext: 'domain', required: true, displayOrder: 0),
                new OptionType(code: 'accountIntegration.microsoft.dns.servicePort', name: 'Service Port', inputType: OptionType.InputType.TEXT, fieldName: 'servicePort', fieldLabel: 'WinRM Port', fieldContext: 'domain', defaultValue: '5985', required: true, displayOrder: 0),
                new OptionType(code: 'accountIntegration.microsoft.dns.credentials', name: 'Credentials', inputType: OptionType.InputType.CREDENTIAL, fieldName: 'type', fieldLabel: 'Credentials', fieldContext: 'credential', required: true, displayOrder: 2, defaultValue: 'local',optionSource: 'credentials',config: '{"credentialTypes":["username-password"]}'),

                new OptionType(code: 'accountIntegration.microsoft.dns.serviceUsername', name: 'Service Username', inputType: OptionType.InputType.TEXT, fieldName: 'serviceUsername', fieldLabel: 'Username', fieldContext: 'domain', required: true, displayOrder: 3,localCredential: true),
                new OptionType(code: 'accountIntegration.microsoft.dns.servicePassword', name: 'Service Password', inputType: OptionType.InputType.PASSWORD, fieldName: 'servicePassword', fieldLabel: 'Password', fieldContext: 'domain', required: true, displayOrder: 4,localCredential: true),
                new OptionType(code: 'accountIntegration.microsoft.dns.zoneFilter', name: 'Zone Filter', inputType: OptionType.InputType.TEXT, fieldName: 'zoneFilter', fieldLabel: 'Zone Filter', required: false, displayOrder: 70),
                new OptionType(code: 'accountIntegration.microsoft.dns.inventoryExisting', name: 'Inventory Existing', inputType: OptionType.InputType.CHECKBOX, defaultValue: 'on', fieldName: 'inventoryExisting', fieldLabel: 'Inventory Existing', fieldContext: 'config', helpBlock:'Inventory existing DNS records.  Not recommended for extra large environments.', displayOrder: 72),
                new OptionType(code:'accountIntegration.microsoft.dns.servicePath', inputType: OptionType.InputType.TEXT, name:'servicePath', category:'accountIntegration.microsoft.dns',
                        fieldName:'servicePath', fieldCode: 'gomorpheus.label.computerName', fieldLabel:'Computer Name', fieldContext:'domain', required:false, enabled:true, editable:true, global:false,
                        placeHolder:null, helpBlock:'', defaultValue:null, custom:false, displayOrder:75),
                new OptionType(code:'accountIntegration.microsoft.dns.serviceFlag', inputType: OptionType.InputType.CHECKBOX, name:'serviceFlag', category:'accountIntegration.microsoft.dns',
                        fieldName:'serviceFlag', fieldCode: 'gomorpheus.label.dnsPointerCreate', fieldLabel:'Create Pointers', fieldContext:'domain', required:false, enabled:true, editable:true, global:false,
                        placeHolder:null, helpBlock:'', defaultValue:'on', custom:false, displayOrder:80)                   
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

    private listZones(AccountIntegration integration) {

        def rtn = [success:false, zoneList:[]]
        def zoneFilters //holds an array of RegEx patterns. Zones matching any filter will be imported
        def config = integration.getConfigMap()
        zoneFilters = config.zoneFilter ? config.zoneFilter.tokenize(",").collect {makeZoneFilterRegex(it)} : null 
        
        try {
            String computerName = integration.servicePath?: ""
            String command = buildGetDnsZoneScript(computerName)
            def rpcData = executeCommandScript(integration, command)

            if (rpcData?.status == 0) {
                log.debug("listZones - integration ${integration.name} - rpcData: ${rpcData}")
                def zoneRecords = new JsonSlurper().parseText(rpcData.cmdOut)
                if (zoneFilters) {
                    log.debug("listZones - integration ${integration.name} - Applying glob style zone filters : ${config.zoneFilter} regEx: ${zoneFilters}")
                    def filteredZoneRecords = zoneRecords.collect {zone -> 
                        // Does this zone name match any of the import zoneFilters
                        if (zoneFilters.find {(zone.ZoneName ==~ it)}) {
                            log.debug("listZones - integration ${integration.name} - found matching zone: {$zone.ZoneName}")
                            return zone
                        } else {
                            log.warn("listZones - integration ${integration.name} - Skipping non-matching zone: {$zone.ZoneName}")
                        }                      
                    }.findAll()                
                    rtn.zoneList = filteredZoneRecords
                    rtn.success = true
                } else {
                    log.debug("listZones - integration ${integration.name} - No Zone filter - importing all zones")
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

    private listRecords(AccountIntegration integration, NetworkDomain domain) {

        def rtn = [success:false, recordList:[]]
        try {
            log.debug("listRecords - integration ${integration.name} - importing zone ${domain.externalId}")
            String computerName = integration.servicePath ?: ""
            String command = buildGetDnsResourceRecordScript(domain.externalId,computerName)
            def rpcData = executeCommandScript(integration, command)
            if (rpcData?.status == 0) {
                rtn.success = true
                def zoneRecords = new JsonSlurper().parseText(rpcData?.cmdOut)
                rtn.recordList = zoneRecords instanceof List ? zoneRecords : [zoneRecords]
                log.debug("listRecords - integration ${integration.name} - zone: ${domain.externalId} resourceRecords: ${zoneRecords.size()}")
            }
            else {
                log.error("listRecords - integration ${integration.name} - zone: ${domain.externalId} - status: ${rpcData.status} - details: ${rpcData.errOut}")
            }
        } catch(e) {
            log.error("listRecords - integration ${integration.name} raised error: ${e.getMessage()}")
        }
        return rtn
    }

    /**
     * Wrapper method to execute the custom built Powershell command string via the Morpheus rpc process
     * and handle the custom response for this plugin. The return object is a map returned
     * in the TaskResult.data property which is interpretted by handleTaskResult
     * 
     * @param integration 
     * @param commandScript
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
            result = morpheusContext.executeWindowsCommand(opts.host,winrmPort,opts.username,opts.password,command,true,opts.elevated ? true: false).blockingGet()
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
        def credentialService = morpheusContext.getAccountCredential()
        def config = integration.getConfigMap()
        log.debug("getRpcConfig - integration: ${integration.name} - credentialData : ${integration.credentialData}")
        def rtn = [:]
        rtn.name = integration.name
        rtn.host = integration.serviceUrl
        rtn.username = integration.credentialData?.username ?: integration.serviceUsername
        rtn.password = integration.credentialData?.password ?: integration.servicePassword
        rtn.inventoryExisting = config.inventoryExisting
        rtn.port = integration.servicePort?.toInteger() ?: 5985
        //rtn.elevated = computerName ? true : false
        rtn.elevated = false // never use the JRuby if possible
        log.debug("getRpcConfig - integration: ${integration.name} - rtn: ${rtn}")
        return rtn
    }

    /**
     * Parse a list of strings from Powershell Format-List cmdlet. Output will be a stream of Key : Value pairs 
     * delimited by newline. Repeating key name signals a new instance of the object
     * rtn is a List of Map objects
     * 
     * Note that key names are Pascal Case as per the Microsoft Powershell standards.
     * Keys returned are dependant on the Powershell XML Formatters and could change in the future
     * for Dns Resource records these are the current key names
     
     * [DistinguishedName: ,HostName: ,RecordType: ,Type: ,RecordClass: ,TimeToLive: ,TimeStamp: ,RecordData: ]
     *
     * @param data 
     */
    private static parseListSet(data) {
        def rtn = []
        def lines = data.tokenize('\n')
        def keyList = []
        if(lines?.size() > 1) {
            def currentObj = [:]
            lines.eachWithIndex { line, index ->
                if(line.length() > 1) {
                    def lineTokens = line.tokenize(':')
                    if(lineTokens.size() > 0) {
                        def lineKey = lineTokens[0].trim()
                        def keyMatch = keyList.find{it == lineKey}
                        if(lineTokens.size() > 1) {
                            if(keyMatch) {
                                rtn << currentObj
                                keyList = []
                                currentObj = [:]
                                currentObj[lineKey] = lineTokens[1..-1].join(':').trim()
                            } else {
                                currentObj[lineKey] = lineTokens[1..-1].join(':').trim()
                            }
                        }
                        keyList << lineKey
                    }
                }
            }
            if(currentObj?.size() > 0)
                rtn << currentObj
            log.debug("parseListSet: ${rtn?.size()}")
        }
        return rtn
    }


    /**
    * TaskResult exitCode is not always set by the rpc service to the DNS Cmdlet error code
    * In this implementation, the Microsoft DNS Error Code (non zero) if raised will be returned as part
    * of a json string in the TaskResult data property
    * 
    * taskResult.data = {
    *   "status": "<rpc error code or 0>, 
    *   "cmdOut": "<success cmdlet output>" , 
    *   "errOut": {error object containing detailed Microsoft properties and mandatory message property conaining error text}
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
    private handleTaskResult(TaskResult result) {

        def jsonSlurper = new JsonSlurper()
        def rpcData = [:]
        
        // Inspect TaskResult data property for a valid response from the Rpc process
        if (result?.data) {
            try {
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
     * returns a map with an overall isValid true/false and a map individually tested items and thier validation status
     *  [isValid : true/false, testedItems:[item : valid true or false] ]
     */
    private validateDnsRecord(String domain, String name, String rrType, String recordData, Integer ttl) {

        Pattern validHost = Pattern.compile('^[a-zA-Z0-9-_\\.]+$')
        def ret = [isValid:true, testedItems: [:]]

        try {
            ret.testedItems.domain = (domain) ? true : false
        }
        catch (e) {
            ret.testedItems.domain = false
            log.warn("validateDnsRecord - Network Domain valkidation failed with exception ${e}")
        }
        try {
            if (supportedRrType(rrType)) {
                ret.testedItems.type = true
                if (rrType.toUpperCase() == "A") {
                    ret.testedItems.content = NetworkUtility.validateIpAddr(recordData)
                } else {
                    ret.testedItems.content = (recordData ==~ validHost)
                }
            } else {
                ret.testedItems.type = false
            }  
            ret.testedItems.name = (name ==~ validHost)
            ret.testedItems.ttl = (ttl >= 0)
            ret.isValid = (ret.testedItems.find {it.value == false} == null) 
        }
        catch (e) {
            ret.isValid = false
            log.warn("validateDnsRecord - NetworkDomainRecord validation failed with exception ${e}")
        }
        log.info("validateDnsRecord - ${ret}")
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
     * If using a jump server this Powershell securely caches the credential inside the profile
     * of the user on the jump server. The credential can only be used by the user who created it and
     * from the same server (Uses Windows DPAPI)
     * Encrypted pwd will be saved to %LOCALAPPDATA%\dnsCred.xml within the users profile
    */
    private String buildCacheCredentialScript(String username, String password) {
        def codeBlock = '''
        $exportCredential = {
            param($username,$password)
            $Ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
            try {
                $CacheFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
                $SS = ConvertTo-SecureString -String $password -AsPlainText -Force
                $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $SS)
                $Cred | Export-CliXml -Path $CacheFile -ErrorAction Stop
                $ret.cmdOut=[PSCustomObject]@{username=$username;cacheFile=$CacheFile}
            }
            catch {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
            $ret
        }
        $ReturnStatus = Invoke-Command -Scriptblock $exportCredential -ArgumentList "<%username%>","<%password%>"
        $ReturnStatus | ConvertTo-Json -depth 2 -Compress
        '''
        log.debug("buildCacheCredentialScript - Building script to securely cache credentials for ${username} in LOCALAPPDATA:dnsCred.xml")
        String runCmd = codeBlock.stripIndent().replace("<%username%>",username).replace("<%password%>",password)
        // Dont debug runCmd as it contains creds
        return runCmd        
    }


    /**
     * If using a jump server this Powershell securely caches the password so the credential
     * can be safely created without passing the password.
     * Encrypted pwd will be saved to %LOCALAPPDATA%\DnsSecureString.ss within the users profile
     */
    private String buildTestServiceCredentialScript(String computerName) {

        def codeBlock = '''
            $TestCredBlock = {
		        $Ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                $userIdentity =  [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $userPrincipal = [System.Security.Principal.WindowsPrincipal]$UserIdentity
                $Groups=$userIdentity.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
                $Ret.cmdOut = [PSCustomObject]@{
                    userId=$userIdentity.Name;
                    authenticationType=$userIdentity.AuthenticationType;
                    isAdmin=$UserPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
                    inGroups=$Groups;
                    dnsServer=$Null
                }
                try {
                    $Ret.cmdOut.dnsServer = Get-DnsServerSetting -ErrorAction Stop | Select-Object -Property computerName, @{n="version";e={"{0}.{1}.{2}" -f $_.MajorVersion,$_.MinorVersion,$_.BuildNumber}}
                }                
                catch {
                    $Ret.status = 2
                    $Ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
                }
                $Ret
            }
            $Params = @{ScriptBlock=$TestCredBlock}
            $CachedCredFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
	        $computer = "<%computer%>"
            if ($computer) {
                $Params.Add("ComputerName",$computer)
                if (Test-Path -Path $CachedCredFile) {
                    $cred = Import-CliXml -Path $CachedCredFile
                    $Params.Add("Credential",$cred)
                }
            }
            $ReturnStatus = Invoke-Command @Params
            $ReturnStatus | ConvertTo-Json -depth 2 -Compress
        '''
        if (computerName) {
            log.debug("buildTestServiceCredentialScript - Building script to test access to DNS Services on ${computerName} using secure cached credential")
        } else {
            log.debug("buildTestServiceCredentialScript - Building script to test access to DNS Services")
        }
        String runCmd = codeBlock.stripIndent().replace("<%computer%>",computerName)
        log.debug("buildTestServiceCredentialScript - ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Adding a Dns Resource record
     * Specify the Resource Record to be created (rrType). Supported options can be clearly seen in the switch statement
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     *
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildAddDnsServerRecordScript(String rrType, String name, String zone, String recordData, Integer ttl, Boolean createPtrRecord, String computerName ) {

        def codeBlock = '''
            $AddBlock = {
                param($rrType,$name,$zone,$data,$ttl,$createPtr)
                $Ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                $TS = New-TimeSpan -seconds $ttl
                switch ($rrType) {
                    "A"     {$DataPropertyName="IpV4Address"; $RTypeParameterName="A"; $SupportsCreatePtr=$True}
                    "AAAA"  {$DataPropertyName="IpV6Address"; $RTypeParameterName="AAAA"; $SupportsCreatePtr=$True}
                    "CNAME" {$DataPropertyName="HostNameAlias"; $RTypeParameterName="CNAME"; $SupportsCreatePtr=$False}
                    "PTR"   {$DataPropertyName="PtrDomainName"; $RTypeParameterName="PTR"; $SupportsCreatePtr=$False}
                    default {$Ret.status=1;$Ret.ErrOut=[PSCustomObject]@{message="Resource Record type $($rrType) not supported by this plugin"}}
                }
                try {
                    $GetParams = @{Name=$name;ZoneName=$zone;RRType=$rrType}
                    $AddParams = @{Name=$name;ZoneName=$zone;$RTypeParameterName=$True;TimeToLive=$TS;$DataPropertyName=$data;AllowUpdateAny=$True}
                    if ($SupportsCreatePtr) {$AddParams.Add("CreatePtr",$createPtr)}
                    $Ret.cmdOut = Add-DnsServerResourceRecord @AddParams -ErrorAction Stop
                    if($?) {
                        $Ret.CmdOut = Get-DnsServerResourceRecord @GetParams -ErrorAction Stop | Format-List | Out-String -width 512 
                    }
                }
                catch {
                    $Ret.status = $_.Exception.ErrorData.error_Code
                    $Ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
                    }
                $Ret
            }
            $Params = @{ScriptBlock=$AddBlock;ArgumentList="<%type%>","<%name%>","<%zone%>","<%data%>",<%ttl%>,<%createptr%>}
            $CachedCredFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
	        $computer = "<%computer%>"
            if ($computer) {
                $Params.Add("ComputerName",$computer)
                if (Test-Path -Path $CachedCredFile) {
                    $cred = Import-CliXml -Path $CachedCredFile
                    $Params.Add("Credential",$cred)
                }
            }
            $ReturnStatus = Invoke-Command @Params
            $ReturnStatus | ConvertTo-Json -depth 2 -Compress       
        '''

        def createPtr = createPtrRecord ? '$True' : '$False'
        def ttlString = ttl ? ttl.toString() : "3600"
        String runCmd = codeBlock.stripIndent().replace("<%type%>",rrType).replace("<%name%>",name).replace("<%zone%>",zone).replace("<%data%>",recordData).replace("<%ttl%>",ttlString).replace("<%createptr%>",createPtr).replace("<%computer%>",computerName)
        log.info("buildAddDnsServerRecordScript - Building script to add ${rrType} record - host: ${name}, zone: ${zone}, recordData: ${recordData}, ttl : ${ttlString}, createPtr: ${createPtrRecord ? 'True' : 'False'}")
        log.debug("buildAddDnsServerRecordScript : ${runCmd}")
        return runCmd
    }

    /**
     * Powershell ScriptBlock for Removing a Dns Resource record
     * Specify the Resource Record to be Deleted (rrType). Supported options can be clearly seen in the switch statement
     * The ScriptBlock is executed using InvokeCommand on the local server unless a computerName is supplied
     * values surrounded by <% %> are replace by the corresponding parameters before the command string is returned ready for execution
     */
    private String buildRemoveDnsServerRecordScript(String rrType, String name, String zone, String recordData, String computerName) {

        def codeBlock = '''
            $RemoveBlock = {
                param($rrType,$name,$zone,$data)
                $Ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                $RemoveParams = @{RRType=$rrType;Name=$name;ZoneName=$zone;RecordData=$data;Force=$true}
                try {
                    $Ret.cmdOut=Remove-DnsServerResourceRecord @RemoveParams -ErrorAction Stop
                }
                catch {
                    $Ret.status = $_.Exception.ErrorData.error_Code
                    $Ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
                }
                $Ret
            }
            # Invoke-Command using parameter splatting
            $Params = @{ScriptBlock=$RemoveBlock;ArgumentList="<%type%>","<%name%>","<%zone%>","<%data%>"}
            $CachedCredFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
	        $computer = "<%computer%>"
            if ($computer) {
                $Params.Add("ComputerName",$computer)
                if (Test-Path -Path $CachedCredFile) {
                    $cred = Import-CliXml -Path $CachedCredFile
                    $Params.Add("Credential",$cred)
                }
            }
            $ReturnStatus = Invoke-Command @Params
            $ReturnStatus | ConvertTo-Json -depth 2 -Compress        
        '''
        String runCmd = codeBlock.stripIndent().replace("<%type%>",rrType).replace("<%name%>",name).replace("<%zone%>",zone).replace("<%data%>",recordData).replace("<%computer%>",computerName)
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
    private String buildGetDnsZoneScript(String computerName) {

        def codeBlock = '''
            $GetZoneBlock = {
                $Ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                try {   
                    $Ret.cmdOut=Get-DnsServerZone -ErrorAction Stop | Select-Object -Property ZoneName | ConvertTo-Json -Compress
                }
                catch {
                    $Ret.status = $_.Exception.ErrorData.error_Code
                    $Ret.errOut=$_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
                }
                $Ret
            }
            $Params = @{ScriptBlock=$GetZoneBlock}
            $CachedCredFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
	        $computer = "<%computer%>"
            if ($computer) {
                $Params.Add("ComputerName",$computer)
                if (Test-Path -Path $CachedCredFile) {
                    $cred = Import-CliXml -Path $CachedCredFile
                    $Params.Add("Credential",$cred)
                }
            }
            $ReturnStatus = Invoke-Command @Params
            $ReturnStatus | ConvertTo-Json -Compress  
        '''    
        String runCmd = codeBlock.stripIndent().replace("<%computer%>",computerName)
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
    private String buildGetDnsResourceRecordScript(String zone, String computerName) {
        log.info("TestingZoneBuild: ${zone}")

        def codeBlock = '''
            $GetZoneRecordBlock = {
                param($zone)
                $Ret = [PSCustomObject]@{
                    status = 0
                    cmdOut = $null
                    errOut = $null
                }

                try {
                    Set-Alias -Name gdnsr -Value Get-DnsServerResourceRecord
                    $recordTypes = "A", "TXT", "MX", "CNAME", "PTR", "AAAA", "MX", "NS", "SOA"
                    $res = foreach ($type in $recordTypes) {
                        gdnsr -ZoneName $zone -RRType $type | Select-Object -Property RecordType, comments, HostName, DistinguishedName, @{
                            Name = "TimeToLive"
                            Expression = { $_.TimeToLive.TotalSeconds }
                        }, @{
                            Name = "RecordData"
                            Expression = {
                                $rd = $_
                                switch ($type) {
                                    "A"     { $rd.RecordData.IPv4Address.ToString() }
                                    "TXT"   { $rd.RecordData.DescriptiveText.ToString() }
                                    "MX"    { $rd.RecordData.MailExchange.ToString() }
                                    "CNAME" { $rd.RecordData.HostNameAlias.ToString() }
                                    "PTR"   { $rd.RecordData.PtrDomainName.ToString() }
                                    "AAAA"  { $rd.RecordData.IPv6Address.ToString() }
                                    "MX"    { $rd.RecordData.MailExchange.toString() }
                                    "NS"    { $rd.RecordData.NameServer.toString() }
                                    "SOA"   { $rd.RecordData.ResponsiblePerson.toString() }
                                }
                            }
                        }
                    }
                    $Ret.cmdOut = $res | ConvertTo-Json -Compress
                } catch {
                    $Ret.status = $_.Exception.ErrorData.error_Code
                    $Ret.errOut=$_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
                }

                $Ret
            }

            $P = @{ScriptBlock = $GetZoneRecordBlock;ArgumentList = "<%zone%>"}
            $ccf = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "dnsCred.xml"
            $computer = "<%computer%>"
            if ($computer) {
                $P.Add("ComputerName", $computer)
                if (Test-Path -Path $ccf) {
                    $cred = Import-CliXml -Path $ccf
                    $P.Add("Credential", $cred)
                }
            }
            (Invoke-Command @P) | ConvertTo-Json -Compress
        '''

        String runCmd = codeBlock.stripIndent().replace("<%zone%>",zone).replace("<%computer%>",computerName)
        log.debug("buildGetDnsResourceRecordScript - Building script to get zone resource records for zone ${zone}")
        log.debug("buildGetDnsResourceRecordScript : ${runCmd}")
        return runCmd
    }
 
}
