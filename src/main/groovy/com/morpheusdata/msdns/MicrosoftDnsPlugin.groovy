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

import com.morpheusdata.core.Plugin
import com.morpheusdata.views.HandlebarsRenderer

/**
 * The entrypoint of the Microsoft DNS Plugin. This is where multiple providers can be registered (if necessary).
 * In the case of Microsoft DNS a simple DNS Provider is registered that enables functionality for those areas of automation.
 * 
 * @author David Estes 
 */
class MicrosoftDnsPlugin extends Plugin {

	@Override
	String getCode() {
		return 'morpheus-msdns-plugin'
	}

	@Override
	void initialize() {
		MicrosoftDnsProvider msdnsProvider = new MicrosoftDnsProvider(this, morpheus)
		this.pluginProviders.put("microsoft.dns", msdnsProvider)
		this.setName("Microsoft DNS")
		this.setAuthor("Stephen Potts")
		this.setRenderer(new HandlebarsRenderer(this.classLoader))
		MicrosoftDnsPluginController msDnsApi = new MicrosoftDnsPluginController(this, morpheus)
		this.controllers.add(msDnsApi)
	}

	/**
	 * Called when a plugin is being removed from the plugin manager (aka Uninstalled)
	 */
	@Override
	void onDestroy() {
		//nothing to do for now
	}
}
