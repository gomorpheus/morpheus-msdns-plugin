# Microsoft DNS Morpheus Plugin

This is the official Morpheus plugin for interacting with Microsoft DNS. This automates functions as it relates to automatically creating DNS Records and cleaning up DNS records both during workload provisioning and manual. It should be noted that if joining a VM to a Domain, this integration is not needed as the Domain joining typically auto creates a zone record. This was originally embedded into morpheus and is being extracted for easier maintenance

### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.

Once the plugin is loaded in the environment. Microsoft DNS becomes available in `Infrastructure -> Network -> Integrations`.

## New with v2.2.0

- Configure the Dns Integration via the MICROSOFT DNS INTEGRATION dialog. To Add a new integration use Administration -> Integrations  and click + NEW INTEGRATION then select Microsoft DNS from the list.
- To make changes to an existing integration use Administration -> Integrations then click on the Integration NAME link to access the dialog

### Microsoft DNS Integration Dialog

- NAME - Enter a name for the Integration
- RPC SERVER -  **NEW** Enter the Name of the server providing access to the Microsoft DNS Services. This is the Server Morpheus will connect to directly. **NOTE** This will also be the DNS Server if accessing the DNS Services directly.
- CREDENTIALS - Provide account credentials for the integration. You may use credentials already stored in Morpheus or create new Username/Password credentials.
- ZONE FILTER - Zones matching the zone filter will be imported and managed by the integration. Leave blank to import DNS forward and reverse zones discovered on the DNS Server. See the section below about using Zone Filters.
- DNS SERVER - If the RPC SERVER is not the server hosting DNS Services then add the FQDN name of the DNS server here. Leave blank if the RPC SERVER is also the DNS Server.
- CREATE POINTERS -  have DNS create a PTR record when the forward record is created. 

### Using ZONE FILTERS

ZONE FILTER was introduced in v2.0 of the plugin. The ZONE FILTER is a comma separated list of glob style filters which can be used to specify the zones that Morpheus will import and sync. Glob style filter apply to the zone name ONLY and at a domain level. Wildcarding stops at the . (period)

The \* character matches any legal Dns character [a-zA-Z0-9_-] 0 or more times 

For example a ZONE FILTER string of

```
*.morpheus.com, *.10.in-addr.arpa, d*.us.morpheus.com
```
would 

**IMPORT** test.morpheus.com, prod.morpheus.com but **NOT** mydomain.test.morpheus.com which has a 4th level

**IMPORT** 32.10.in-addr.arpa, 33.10.in-addr.arpa but **NOT** 12.11.in-addr.arpa or 10.in-addr.arpa (which has 3 levels)

**IMPORT** denver.us.morpheus.com and delaware.us.morpheus.com but **NOT** ohio.us.morpheus.com (wildcard at 4th level)


### Improved Integration Validation

This plugin includes improvements in error handling and validation. Connectivity and access to DNS Services is tested at the time the integration dialog is saved. The Dialog will not save unless validation is passed successfully. The integration dialog will hint where problems occur but you should check the Morpheus Health logs to see detailed messages.

### DNS Record validation and Error Handling

- DNS records are now fully validated before they are created. Only record types A, CNAME and PTR re surrently supported.
- The integration will return an error if a matching DNS record already exists in DNS. This is **new** behaviour and prevents duplicates being added to Morpheus
- All error are logged to the Morpheus Health logs

### Morpheus Custom Powershell Functions

A script module containing the Morpheus Powershell functions required by this integration is contained within this plugin and is copied to the RPC Server where it is stored in the Local profile of the integration user account. This makes the integration much more efficient when executing remote Powershell calls from Morpheus. The downloaded script module is md5 checked on each integration refresh to ensure the contents match the plugin copy. 

### Intermediary Server Support

This plugin uses a technique where Powershell script blocks are executed using Invoke-Command. 

Using securely cached credentials stored in the local user profile on the intemediate server, Invoke-Command can execute script blocks on remote computers (-ComputerName parameter) with specified Credentials (-Credential). Using this method allows for a Kerberos login from the Intermediate Server to the DNS Server overcoming NTLM impersonation restrictions. Credentials are securely cached using Windows DPAPI and can only be access by the computer and user account that cached them. When using an intermediate server 2 methods can be employed to connect the DNS Services. Using winRm the script blocks are invoked on the DNS Server using PS Remoting which will require winRm access on the DNS Server. A second technique is to use WMI rpc calls (where the DNS cmdlets specify a -Computername parameter). In this case the service account will require access to the Microsoft DNS WMI namespace on the DNS Server and in most cases the intermediate windows server must be tusted for delegation.

### AWS Directory Services Support

V2.2 support AWS Active Directory service. 

- Access is only possible via a correctly configured intermediate server (RPC SERVER) hosted in AWS and having the DNS Management Tools installed. 
- The DNS SERVER must be the fully qualified name of one of the AWS Domain controllers.
- The Service Account should be a member of AWS Delegated Domain Name System Administrators, AWS Delegated Kerberos Delegation Administrators and AWS Delegated Server Administrators (for access to RPC SERVER). 
- The RPC SERVER computer object should be trusted for delegation for all Kerberos Services on the AWS Directory Service domain controllers. This can be performed using AD Users and Computers to modify the properties of the RPC SERVER Computer object. Right click the computer object, select properties and open the Delegation tab. Select the Radio button **Trust this computer for delegation to any service (Kerberos Only). Click OK to Save

Note it is possible to finely tune the delegation so that the RPC SERVER computer object can only delegate to specific services if this is required.