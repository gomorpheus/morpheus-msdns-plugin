package com.morpheusdata.msdns

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.model.TaskResult
import com.morpheusdata.model.ComputeServer
import com.morpheusdata.core.data.*
import com.morpheusdata.response.ServiceResponse

import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j

@Slf4j
class MicrosoftDnsPluginRpcService {

    MorpheusContext morpheusContext
    private final static Map errorCodes = [
            0 : [isError: false, msg: "Command completed successfully"],
            5 : [isError: true, msg: "Access Denied - cannot access DNS Service with credentials provided"],
            13 : [isError: true, msg: "The data for the resource value is invalid"],
            9711 : [isError: false, msg: "A matching DNS record already exists"],
            9714 : [isError: false, msg: "The DNS Record does not exist"],
            9715 : [isError: false, msg: "Forward record added but unable to create corresponding PTR Record"],
            9601 : [isError: true, msg: "The DNS Zone does not exist"],
            9563 : [isError: true, msg: "The record could not be created because this part of the DNS namespace has been delegated to another server"],
            1722 : [isError: true, msg: "The server is not a DNS Server - the rpc server is unavailable"]
    ]

    MicrosoftDnsPluginRpcService(MorpheusContext morpheusContext) {
        this.morpheusContext = morpheusContext
        log.info("MicrosoftDnsPluginRpcService - Constructor called - injecting MorpheusContext")
    }

    MorpheusContext getMorpheus() {
        return morpheusContext
    }

    ServiceResponse executeCommand(String command, AccountIntegration integration) {
        //Agent or Winrm??
        TaskResult rpcResult

        //Setup rpc data from the integration
        String rpcHost = integration.serviceUrl
        Integer rpcPort = integration.servicePort?.toInteger() ?: 5985
        String servicePath = integration.servicePath
        String username = integration.credentialData?.username ?: integration.serviceUsername
        String password = integration.credentialData?.password ?: integration.servicePassword
        Map integrationConfig = integration.getConfigMap()
        ServiceResponse rpcCall
        // Are we using Agent or winRm for transport
        String rpcTransport = (integrationConfig?.agentRpc && integrationConfig?.agentRpc == "on") ? "agent" : "winrm"

        if (rpcTransport == "agent") {
            //TODO locate server record for rpcServer - need it for the agent
            log.info("executeCommand - Using Morpheus Agent as rpc Transport")
            //Ensure we get the non-qualified rpcHost
            ComputeServer server
            try {
                rpcHost = integration.serviceUrl.tokenize(".").first()
                server = getMorpheus().getAsync().getComputeServer().find(
                    new DataQuery().withFilters(
                        new DataAndFilter(
                                new DataOrFilter(
                                        new DataFilter("hostname","==",integration.serviceUrl),
                                        new DataFilter("hostname","==",rpcHost)
                                ),
                                new DataFilter("agentInstalled","==",true)
                        ))).blockingGet()
            }
            catch (e) {
                log.error("executeCommand - Error locating ComputeServer for Agent rpc transport ${rpcHost} - Exception ${e.getMessage()}")
                return ServiceResponse.error("Agent RPC Process - failed to locate ComputeServer with Agent installed.")
            }
            if (server) {
                log.info("executeCommand - located ComputeServer with hostname ${server?.hostname} - apiKey ${server?.apiKey} - Agent Version ${server.agentVersion}")
                try {
                    rpcResult = getMorpheus().executeCommandOnServer(server,command,false,null,null,null,null,null,true,false,false).blockingGet()
                    log.debug("executeCommand - rpcType:agent - Results -  ${rpcResult.dump()}")
                }
                catch (e) {
                    log.error("executeCommand - Agent rpc process raised exception ${e.getMessage()}")
                    return ServiceResponse.error("Agent RPC Process failed to connect - check Server in Morpheus")
                }
            } else {
                log.warn("executeCommand - Error locating ComputeServer for Agent rpc transport ${rpcHost}")
                return ServiceResponse.error("Agent RPC Process - failed to locate ComputeServer with Agent installed - ${rpcHost}")
            }
        } else {
            log.info("executeCommand - Using winrm as rpc Transport")
            try {
                rpcResult = getMorpheus().executeWindowsCommand(rpcHost, rpcPort, username, password, command, true, false).blockingGet()
                log.debug("executeCommand - rpcType:winrm - Results -  ${rpcResult.dump()}")
            }
            catch (e) {
                log.error("executeCommand - WinRm rpc process raised exception ${e.getMessage()}")
                return ServiceResponse.error("Winrm RPC Process failed to connect - check credentials")
            }
        }
        if (rpcResult) {
            Map rpcData = processTaskResult(rpcResult)
            rpcCall = ServiceResponse.prepare(rpcData)
            rpcCall.setErrorCode(rpcData.status?.toString())
            if (rpcResult.success) {
                log.debug("executeCommand - TaskResult using transport ${rpcTransport} - ${rpcResult.toMap()}")
                rpcCall.setSuccess(!(isErrorLevel(rpcData.status)))
                if (rpcCall.success) {
                    rpcCall.setMsg("Successful rpc response from ${rpcHost} via ${rpcTransport}: ${getErrorMsg(rpcData.status)}")
                    // rpcCall successful but it could be masked - log a warning if non-zero status
                    if (rpcData.status > 0) {
                        log.warn("executeCommand - Masking error from DNS - ${rpcHost} via ${rpcTransport}. Status: ${rpcData.status} : ${getErrorMsg(rpcData.status)}")
                    } else {
                        log.info("executeCommand - ${rpcHost} via ${rpcTransport}: ${getErrorMsg(rpcData.status)}")
                    }
                } else {
                    log.warn("executeCommand - rpc completed ok but response indicates a failure status ${rpcData}")
                    rpcCall.setMsg("Warning: Unsuccessful rpc response from ${rpcHost} via ${rpcTransport}. Status: ${rpcData.status} : ${getErrorMsg(rpcData.status)}")
                    rpcCall.addError("executeCommand",rpcData.errOut?.message)
                }
            } else {
                rpcCall.success = false
                if (rpcResult.exitCode) {
                    log.warn("executeCommand - Rpc Process on host ${rpcHost} failed returning exitCode ${rpcResult.exitCode}")
                    rpcCall.addError("executeCommand","rpc process on host ${rpcHost} returned exitCode ${rpcResult.exitCode}")
                } else {
                    log.error("executeCommand - Rpc process failed to login on host ${rpcHost} with the credentials supplied :${username}")
                    rpcCall.addError("executeCommand","Rpc process failed to login on host ${rpcHost} with the credentials supplied :${username}")
                }
            }
            return rpcCall
        } else {
            return ServiceResponse.error("Rpc Process on Host ${rpcHost} failed to return a TaskResult")
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
    private static Map processTaskResult(TaskResult result) {

        JsonSlurper jsonSlurper = new JsonSlurper()
        Map rpcData = [:]

        // Inspect TaskResult data property for a valid response from the Rpc process
        if (result?.data) {
            try {
                log.debug("processTaskResult - Raw json rpcData ${result.data}")
                rpcData = jsonSlurper.parseText(result.data) as Map
                log.debug("processTaskResult - MicrosoftDns Rpc result Status ${rpcData}")
            }
            catch (e) {
                log.warn("processTaskResult - Unable to process MicrosoftDns return json. TaskResult exitCode: ${result.exitCode} - exception ${e}")
                rpcData.status = 1
                rpcData.cmdOut = null
                rpcData.errOut = [message: "Unable to interpret the Rpc json response ${e.getMessage()}"]
            }
        } else {
            log.error("processTaskResult - MicrosoftDns Rpc result returned no usable data. TaskResult.data is null")
            rpcData.status = 1
            rpcData.cmdOut = null
            rpcData.errOut = [message: "Rpc process failed to return any usable data. Check Credentials and rpc details"]
        }
        return rpcData
    }

    static Boolean isErrorLevel(code) {
        return errorCodes.getOrDefault(code,[isError: true,msg: "Unknown Message for error code ${code}"]).isError
    }

    static String getErrorMsg(code) {
        return errorCodes.getOrDefault(code,[isError: true,msg: "Unknown Message for error code ${code}"]).msg
    }

}
