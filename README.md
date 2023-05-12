## Microsoft DNS Morpheus Plugin

This is the official Morpheus plugin for interacting with Microsoft DNS. This automates functions as it relates to automatically creating DNS Records and cleaning up DNS records both during workload provisioning and manual. It should be noted that if joining a VM to a Domain, this integration is not needed as the Domain joining typically auto creates a zone record. This was originally embedded into morpheus and is being extracted for easier maintenance

### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.

### Configuring

Once the plugin is loaded in the environment. Microsoft DNS becomes available in `Infrastructure -> Network -> Integrations`.

Configure the Dns Integration via the CREATE MICROSOFT DNS INTEGRATION dialog.

Enter a value for the Integration NAME

If using a jump server or intermediate management server enter the FQDN or Address of this server in the DNS SERVER text box. If not using an intermediary server this should be the FQDN or Address of the DNS Server. In the plugin this option value is known as serviceUrl and must be reachable via WinRm.

Enter the Credentials with access to the Dns Services. Choose stored Credentials or enter Username and Password. Username should be in User Principal Name format

When using a jump server or Intermediate server enter the FQDN or Address of the actual DNS Server in the COMPUTER NAME text box. In the plugin this option value is known as servicePath. The plugin will access the DNS services via this computer

ZONE FILTER New to v2.0 of the plugin. A comma separated list of glob style filters which can be used to specify the zones that Morpheus will import and sync. Glob style filter apply to the zone name ONLY and at a domain level. Wildcarding stops at the . (period) 

The \* character matches any legal Dns character [a-zA-Z0-9_-] 0 or more times 

An example a filter string of

```
*.morpheus.com, *.10.in-addr.arpa, d*.us.morpheus.com
```
would 

**IMPORT** test.morpheus.com, prod.morpheus.com but **NOT** mydomain.test.morpheus.com which has a 4th level

**IMPORT** 32.10.in-addr.arpa, 33.10.in-addr.arpa but **NOT** 12.11.in-addr.arpa or 10.in-addr.arpa (which has 3 levels)

**IMPORT** denver.us.morpheus.com and delaware.us.morpheus.com but **NOT** ohio.us.morpheus.com (wildcard at 4th level)


### Validation

This plugin includes improvements in error handling and validation. Connectivity and access to DNS Services is tested at the time the integration dialog is saved

### Intermediary Server Support

New with v2.1.0

This plugin uses a technique where Powershell script blocks are executed using Invoke-Command. Using securely cached credentials stored in the user profile on the intemediate server, Invoke-Command can execute script blocks on remote computers (-ComputerName parameter) with specified Credentials (-Credential). Using this method allows for a Kerberos login from the Intermediate Server to the DNS Server overcoming NTLM impersonation restrictions. Credentials are securely cached using Windows DPAPI and can only be access by the computer and user account that cached them.

No caching is required if you access the DNS Server directly
