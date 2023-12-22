package com.morpheusdata.msdns

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.OptionSourceProvider
import com.morpheusdata.core.Plugin

class MicrosoftDnsOptionSourceProvider implements OptionSourceProvider{

    Plugin plugin
    MorpheusContext morpheusContext

    MicrosoftDnsOptionSourceProvider(Plugin plugin, MorpheusContext context) {
        this.plugin = plugin
        this.morpheusContext = context
    }

    @Override
    MorpheusContext getMorpheus() {
        return this.morpheusContext
    }

    @Override
    Plugin getPlugin() {
        return this.plugin
    }

    @Override
    String getCode() {
        return "msdns-option-source-plugin"
    }

    @Override
    String getName() {
        return "Microsoft DNS Option Source Plugin"
    }

    @Override
    List<String> getMethodNames() {
        return new ArrayList<String>(["msdnsServiceTypeList"])
    }

    List<Map> msdnsServiceTypeList(args) {
        return [
            [name: "DNS Service is Local", value: "local"],
            [name: "use Wmi to access DNS (default)", value: "wmi"],
            [name: "Use a winRm Session to access DNS", value: "winrm"]
        ]
    }
}