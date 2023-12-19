# Microsoft DNS Morpheus Plugin

## Version 3.2
### Morpheus tested version 6.2.4
### Plugin API version 0.15.7

## Introduction 
This is the official Morpheus plugin for interacting with Microsoft DNS. This automates functions as it relates to automatically creating DNS Records and cleaning up DNS records both during workload provisioning and manually. It should be noted that if joining a Windows VM to an Active Directory Domain, this integration is not needed as the Domain joining typically auto creates a DNS record. This was originally embedded into Morpheus and is being extracted for easier maintenance.

### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.

Once the plugin is loaded in the environment. Microsoft DNS becomes available in `Infrastructure -> Network -> Integrations`.

## New with v3.2   
### Version Alignment
Align the versioning so the the point release matches the supported Morpheus point release. So 3.2 will be compatible with the latest supported Morpheus 6.2 version at the time of release.
### Custom Powershell Script Module
All Morpheus DNS related Powershell functions are contained in a Powershell script file stored within the plugin. The Powershell script is automatically downloaded to the RPC SERVER and stored in the LocalAppData profile for the service account user. The file contents are md5 checked to ensure the file is not tampered with. The module is refreshed from the plugin if the md5 sum does not match.
The module contains custom functions designed to interface with the MsDns Plugin via json.

- Having the Powershell module installed on the RPC SERVER offers some performance benefits as scripts are no longer transferred on each Rpc call.
- The Powershell Functions test rpc connectivity and DNS service connectivity tests on each sync refresh ensuring the integration is healthy
- The module uses a standard json interface between Windows RPC SERVER and Morpheus
- Parsing DNS resource record properties into json is now much faster.

## Morpheus Agent for Rpc
This version prepares the plugin to support the Morpheus Windows Agent as an rpc transport.
NOT supported fully in this release.

## Plugin Integration Controls 

- Configure the Dns Integration via the MICROSOFT DNS INTEGRATION dialog. To Add a new integration use Administration -> Integrations  and click + NEW INTEGRATION then select Microsoft DNS from the list.
- To make changes to an existing integration use Administration -> Integrations then click on the Integration NAME link to access the dialog

### MS DNS Integration Dialog Options

- NAME - Enter a name for the Integration
- RPC SERVER -  Enter the Name of the server providing access to the Microsoft DNS Services. This is the Server Morpheus will connect to directly. **NOTE** This will also be the DNS Server if accessing the DNS Services directly.
- USE AGENT FOR RPC checkbox. **NEW in 3.2** Select this option to have the Plugin use a configured Agent to handle the Morpheus to Windows Rpc connection. The RPC SERVER should be an instance or managed vm and the Morpheus Agent should be configured to Logon As the DNS Service user.
- CREDENTIALS - Provide account credentials for the integration. You may use credentials already stored in Morpheus or create new Username/Password credentials.
- ZONE FILTER was introduced in v2.0 of the plugin. The ZONE FILTER is a comma separated list of glob style filters which can be used to specify the zones that Morpheus will import and sync.
  - Glob style filters apply to the zone name ONLY and at a domain level.
  - The \* character matches any legal Dns character [a-zA-Z0-9_-] 0 or more times.
  - Wildcarding stops at the . (period)
  - Leave blank to import ALL forward and reverse zones
- DNS SERVER - If the RPC SERVER is not the server hosting DNS Services then add the FQDN name of the DNS server here. Leave blank if the RPC SERVER is also the DNS Server.
- SERVICE TYPE - **NEW in 3.2** This text box informs the plugin how the RPC SERVER should contact the DNS SERVER. There are 3 supported options                                        
  - **local** : When the RPC SERVER is the DNS Server local is the default and ONLY option.
  - **wmi** : Use wmi when the RPC SERVER contacts the DNS Server over wmi. This is normally the default when using and intermediate RPC SERVER                       
  - **winrm** : Use this option when the RPC SERVER connects to DNS SERVER over a winrm session. Not often used.                                                    

- CREATE POINTERS -  have DNS create a PTR record when the forward record is created. 
 
### Using Zone Filters
In this example a ZONE FILTER string of
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

- DNS records are now fully validated before they are created. Only record types A, CNAME and PTR are currently supported.
- The integration will return an error if a matching DNS record already exists in DNS. This is **new** behaviour and prevents duplicates being added to Morpheus
- All error are logged to the Morpheus Health logs

### Intermediary Server Support

To use an intermediate server: 
- enter the fqdn of the intermediate server as the RPC SERVER
- enter the fqdn of the Dns Server as DNS SERVER
- enter **wmi** or **winrm** as the SERVICE TYPE

This plugin uses a technique where Powershell script blocks are executed using Invoke-Command.
Using securely cached credentials stored in the local user profile on the intermediate server, Invoke-Command can execute script blocks on remote computers (-ComputerName parameter) with specified Credentials (-Credential). 
Using this method allows for a Kerberos login from the Intermediate Server to the DNS Server overcoming NTLM impersonation restrictions. Credentials are securely cached using Windows DPAPI and can only be access by the computer and user account that cached them. When using an intermediate server 2 methods can be employed to connect the DNS Services.
Using winrm the script blocks are invoked on the DNS Server using PS Remoting which will require winRm access on the DNS Server. A second technique is to use WMI rpc calls (where the DNS cmdlets specify a -Computername parameter). In this case the service account will require access to the Microsoft DNS WMI namespace on the DNS Server and in most cases the intermediate windows server must be tusted for delegation.

### AWS Directory Services Support

V2.2 support AWS Active Directory service. 

- Access is only possible via a correctly configured intermediate server (RPC SERVER) hosted in AWS and having the DNS Management Tools installed. 
- The DNS SERVER must be the fully qualified name of one of the AWS Domain controllers.
- The Service Account should be a member of AWS Delegated Domain Name System Administrators, AWS Delegated Kerberos Delegation Administrators and AWS Delegated Server Administrators (for access to RPC SERVER). 
- The RPC SERVER computer object should be trusted for delegation for all Kerberos Services on the AWS Directory Service domain controllers. This can be performed using AD Users and Computers to modify the properties of the RPC SERVER Computer object. Right click the computer object, select properties and open the Delegation tab. Select the Radio button **Trust this computer for delegation to any service (Kerberos Only). Click OK to Save

Note it is possible to finely tune the delegation so that the RPC SERVER computer object can only delegate to specific services if this is required.