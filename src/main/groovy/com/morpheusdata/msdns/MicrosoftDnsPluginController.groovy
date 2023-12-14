/*
* Copyright 2023 the original author or authors.
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

import com.morpheusdata.core.Plugin
import groovy.util.logging.Slf4j
import com.morpheusdata.web.Route
import com.morpheusdata.web.PluginController
import com.morpheusdata.views.HTMLResponse
import com.morpheusdata.views.JsonResponse
import com.morpheusdata.views.ViewModel
import com.morpheusdata.core.MorpheusContext
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import com.morpheusdata.model.Permission
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.response.ServiceResponse

@Slf4j
class MicrosoftDnsPluginController implements PluginController {

    MorpheusContext morpheusContext
    MicrosoftDnsPlugin plugin
    
    public MicrosoftDnsPluginController(MicrosoftDnsPlugin plugin, MorpheusContext morpheusContext) {
        this.plugin = plugin
        this.morpheusContext = morpheusContext
        log.info("MicrosoftDnsPluginController - Constructor called")
    }

    @Override
    public String getCode() {
        return 'msdns-controller'
    }

    @Override
    String getName() {
        return 'MSDNS Controller'
    }

    @Override
    MorpheusContext getMorpheus() {
        return morpheusContext
    }

    @Override
    Plugin getPlugin() {
        return plugin
    }

    List<Route> getRoutes() {
        log.info("getRoutes - Adding plugin controller routes")
        return [
            Route.build("/msdns/service", "testService", [Permission.build("admin-cm","full")])
        ]
    }


    def testService(ViewModel<Map> model) {
        log.info("testService - Testing integration service profile for model - ${model.object}")
        def provider = getPlugin().getProviderByCode('microsoft.dns')
        ViewModel<Map> dataModel = new ViewModel<Map>()
        dataModel.object = [
            integrationId: 0, 
            integrationDetails: "The integrationId is not a valid Microsoft DNS Integration", 
            rpcInfo: "Please use the query parameter /?integrationId=n to specify a valid Microsoft DNS integration"
        ]        
        long integrationId

        if (model.object?.integrationId) {
            try {
                integrationId = Long.parseLong(model.object?.integrationId)
            }
            catch (e) {
                integrationId = 0
            }
            if (integrationId > 0) {
                ServiceResponse<Map> serviceInfo = provider.getIntegrationServiceProfile(integrationId)
                log.debug("View Controller got ServiceResponse : ${serviceInfo}")
                if (serviceInfo) {
                    log.info("testService - got Success Response")
                    dataModel.object.integrationId = integrationId
                    dataModel.object.success = serviceInfo.success
                    dataModel.object.msg = serviceInfo.msg
                    dataModel.object.error = JsonOutput.prettyPrint(JsonOutput.toJson(serviceInfo.getErrors()))
                    dataModel.object.integrationDetails = "Discovered service profile for Microsoft DNS integration : ${integrationId}"
                    dataModel.object.rpcInfo = JsonOutput.prettyPrint(JsonOutput.toJson(serviceInfo.data))
                } else {
                    log.warn("testService - cannot load details for integration ${integrationId} - ${serviceInfo.getError()}")
                }
            }
        } else {
            dataModel.object.integrationDetails = "Please specify a Microsoft DNS integrationId"
        }

        log.debug("testService - About to render ViewModel - ${dataModel}")
        getPlugin().getRenderer().renderTemplate("rpcProfile", dataModel)           
    }

}
