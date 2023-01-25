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
     * @param record The domain record that is being requested for creation. All the metadata needed to create teh record
     *               should exist here.
     * @param opts any additional options that may be used in the future to configure behavior. Currently unused
     * @return a ServiceResponse with the success/error state of the create operation as well as the modified record.
     */
    @Override
    ServiceResponse createRecord(AccountIntegration integration, NetworkDomainRecord record, Map opts) {
        log.info("Creating DNS Record via Microsoft DNS...")

        def createPtrRecord = false
        def fqdn = record.fqdn
        def domainName
        def computerName
        try {
            def recordType = record.type
            def recordData = record.content
            def command
            if(!fqdn?.endsWith('.')) {
                fqdn = fqdn + '.'
            }
            domainName = record.networkDomain.name
            computerName = integration.servicePath
            createPtrRecord = (integration.serviceFlag == null || integration.serviceFlag)
            if(recordType == 'CNAME') {
                command = "Add-DnsServerResourceRecordCName -Name \"${fqdn}\" -HostNameAlias \"${recordData}\" -ZoneName \"${domainName}\""
            } else {
                if(createPtrRecord) {
                    command = "Add-DnsServerResourceRecordA -Name \"${fqdn}\" -ZoneName \"${domainName}\" -AllowUpdateAny -IPv4Address \"${recordData}\" -CreatePtr -TimeToLive 01:00:00"

                } else {
                    command = "Add-DnsServerResourceRecordA -Name \"${fqdn}\" -ZoneName \"${domainName}\" -AllowUpdateAny -IPv4Address \"${recordData}\" -TimeToLive 01:00:00"
                }
            }
            if(computerName) {
                command += " -ComputerName ${computerName}"
            }
            def commandOpts = getRpcConfig(integration, computerName)
            def results = executeCommand(command, commandOpts)
            log.info("add dns results: ${results}")

            if(results.success){
                return new ServiceResponse<NetworkDomainRecord>(true,null,null,record)
            } else {
                log.error("An error occurred trying to create a dns record {} via {}: Exit {}: {}",fqdn,integration.name, results.exitCode,results.error ?: results.output)
                return new ServiceResponse<NetworkDomainRecord>(false,"Error Creating DNS Record ${results.error}",null,record)
            }
        } catch(e) {
            log.error("createRecord error: ${e}", e)
        }
        return ServiceResponse.error("Unknown Error Occurred Creating Microsoft DNS Record",null,record)
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
        try {
                String recordType = record.type
                String fqdn = record.fqdn
                if(!fqdn.endsWith('.')) {
                    fqdn = fqdn + '.'
                }
                String recordData = record.recordData
                String domainName = record.networkDomain.name
                String command
                String computerName = integration.servicePath
                if(recordType == 'CNAME') {
                    command = "Remove-DnsServerResourceRecord -Force -ZoneName \"${domainName}\" -RRType \"CNAME\" -Name \"${fqdn}\" -RecordData \"${recordData}\""
                } else if(recordType == 'PTR'){
                    command = "Remove-DnsServerResourceRecord -Force -ZoneName \"${domainName}\" -RRType \"PTR\" -Name \"${fqdn}\" -RecordData \"${recordData}\""
                } else {
                    command = "Remove-DnsServerResourceRecord -Force -ZoneName \"${domainName}\" -RRType \"A\" -Name \"${fqdn}\" -RecordData \"${recordData}\""
                }
                if(computerName) {
                    command += " -ComputerName ${computerName}"
                }
                def commandOpts = getRpcConfig(integration, computerName)
                def results = executeCommand(command, commandOpts)
                if(results.success) {
                    return ServiceResponse.success()
                } else {
                    return ServiceResponse.error("Error removing Microsoft DNS Record ${record.name} - ${results.error}")
                }
        } catch(e) {
            log.error("deleteRecord error: ${e}", e)
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
            log.debug("online: {} - {}", rpcConfig.host, hostOnline)
            def testResults
            // Promise
            if(hostOnline) {
                Date now = new Date()
                cacheZones(integration)
                cacheZoneRecords(integration)
                log.info("Sync Completed in ${new Date().time - now.time}ms")
                morpheus.integration.updateAccountIntegrationStatus(integration, AccountIntegration.Status.ok).subscribe().dispose()
            } else {
                morpheus.integration.updateAccountIntegrationStatus(integration, AccountIntegration.Status.error, 'Microsoft DNS not reachable')
            }
        } catch(e) {
            log.error("refresh Microsoft DNS error: ${e}", e)
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
        try {
            ServiceResponse rtn = new ServiceResponse()
            def computerName = integration.servicePath
            def command = "Get-DnsServerSetting"
            if(computerName) {
                command = "Get-DnsServerSetting -ComputerName ${computerName}"
            }
            rtn.errors = [:]
            if(!integration.name || integration.name == ''){
                rtn.errors['name'] = 'name is required'
            }
            if(!integration.serviceUrl || integration.serviceUrl == ''){
                rtn.errors['serviceUrl'] = 'DNS Server is required'
            }
            if((!integration.servicePassword || integration.servicePassword == '') && (!integration.credentialData?.password || integration.credentialData?.password == '')){
                rtn.errors['servicePassword'] = 'password is required'
            }
            if((!integration.serviceUsername || integration.serviceUsername == '') && (!integration.credentialData?.username || integration.credentialData?.username == '')){
                rtn.errors['serviceUsername'] = 'username is required'
            }
            if(rtn.errors.size() > 0){
                rtn.success = false
                return rtn
            }

            def commandOpts = getRpcConfig(integration,computerName)
            def results = executeCommand(command, commandOpts)
            log.info("validate dns results: ${results}")
            if(!results.success) {
                return ServiceResponse.error('dns services not found on host')
            } else {
                return ServiceResponse.success()
            }
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
     * @param poolServer
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
            return networkDomain
        }
        morpheus.network.domain.create(integration.id, missingZonesList).blockingGet()
    }

    /**
     * Given a pool server and updateList, extract externalId's and names to match on and update NetworkDomains.
     * @param poolServer
     * @param addList
     */
    void updateMatchedZones(AccountIntegration integration, List<SyncTask.UpdateItem<NetworkDomain,Map>> updateList) {
        def domainsToUpdate = []
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



        morpheus.network.domain.listIdentityProjections(integration.id).buffer(50).flatMap { Collection<NetworkDomainIdentityProjection> poolIdents ->
            return morpheus.network.domain.listById(poolIdents.collect{it.id})
        }.flatMap { NetworkDomain domain ->
            def listResults = listRecords(integration,domain)


            if (listResults.success) {
                List<Map> apiItems = listResults.recordList as List<Map>

                //Unfortunately the unique identification matching for msdns requires the full record for now... so we have to load all records...this should be fixed

                Observable<NetworkDomainRecord> domainRecords = morpheus.network.domain.record.listIdentityProjections(domain,null).buffer(50).flatMap {domainIdentities ->
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
                    Map<Long, SyncTask.UpdateItemDto<NetworkDomainRecord, Map>> updateItemMap = updateItems.collectEntries { [(it.existingItem.id): it]}
                    return morpheus.network.domain.record.listById(updateItems.collect{it.existingItem.id} as Collection<Long>).map { NetworkDomainRecord domainRecord ->
                        SyncTask.UpdateItemDto<NetworkDomainRecordIdentityProjection, Map> matchItem = updateItemMap[domainRecord.id]
                        return new SyncTask.UpdateItem<NetworkDomainRecord,Map>(existingItem:domainRecord, masterItem:matchItem.masterItem)
                    }
                }.onUpdate { List<SyncTask.UpdateItem<NetworkDomainRecord,Map>> updateItems ->
                    updateMatchedDomainRecords(updateItems)
                }.observe()
            } else {
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
                                 type:record['RecordType']?.toUpperCase(), comments:record.comments, ttl:convertTtlStringToSeconds(record['TimeToLive']),
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
                new OptionType(code: 'accountIntegration.microsoft.dns.credentials', name: 'Credentials', inputType: OptionType.InputType.CREDENTIAL, fieldName: 'type', fieldLabel: 'Credentials', fieldContext: 'credential', required: true, displayOrder: 1, defaultValue: 'local',optionSource: 'credentials',config: '{"credentialTypes":["username-password"]}'),

                new OptionType(code: 'accountIntegration.microsoft.dns.serviceUsername', name: 'Service Username', inputType: OptionType.InputType.TEXT, fieldName: 'serviceUsername', fieldLabel: 'Username', fieldContext: 'domain', required: true, displayOrder: 2,localCredential: true),
                new OptionType(code: 'accountIntegration.microsoft.dns.servicePassword', name: 'Service Password', inputType: OptionType.InputType.PASSWORD, fieldName: 'servicePassword', fieldLabel: 'Password', fieldContext: 'domain', required: true, displayOrder: 3,localCredential: true),
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
        try {
            def computerName = integration.servicePath
            def command = 'Get-DnsServerZone | Format-List | Out-String -width 512'
            if(computerName) {
                command = "Get-DnsServerZone -ComputerName ${computerName} | Format-List | Out-String -width 512"
            }
            def commandOpts = getRpcConfig(integration, computerName)
            def results = executeCommand(command, commandOpts)
            log.debug("results.data: ${results.data}")
            if(results.success) {
                rtn.success = true
                def zoneRecords = parseListSet(results.data)
                rtn.zoneList = zoneRecords
            }
        } catch(e) {
            log.error("listZones error: ${e}", e)
        }
        return rtn
    }

    private listRecords(AccountIntegration integration, NetworkDomain domain) {
        def rtn = [success:false, recordList:[]]
        try {
            def computerName = integration.servicePath
            def command = 'Get-DnsServerResourceRecord -ZoneName "' + domain.externalId + '" | Format-List | Out-String -width 512'
            if(computerName) {
                command = "Get-DnsServerResourceRecord -ComputerName ${computerName}" + ' -ZoneName "' + domain.externalId + '" | Format-List | Out-String -width 512'
            }

            def commandOpts = getRpcConfig(integration, computerName)
            def results = executeCommand(command, commandOpts)
            log.debug("results.data: ${results.data}")
            if(results.success) {
                rtn.success = true
                def zoneRecords = parseListSet(results.data)
                rtn.recordList = zoneRecords
            }
        } catch(e) {
            log.error("listRecords error: ${e}", e)
        }
        return rtn
    }

    TaskResult executeCommand(String command, Map opts) {
        def winrmPort = opts.port && opts.port != 22 ? opts.port : 5985
        def results = morpheusContext.executeWindowsCommand(opts.host,winrmPort,opts.username,opts.password,command,true,opts.elevated ? true: false).blockingGet()
        log.debug("msdns command results for command {}: {}",command,results)
        return results
    }

    /**
     * Generalizes the remote connection information from credential data
     * @param integration
     * @param computerName
     */
    private getRpcConfig(AccountIntegration integration, String computerName=null) {
        def rtn = [host:integration.serviceUrl, username:integration.credentialData?.username ?: integration.serviceUsername, password:integration.credentialData?.password ?: integration.servicePassword, elevated: computerName ? true : false]
    }

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
}
