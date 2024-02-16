# Microsoft DNS Morpheus Plugin

## Version 3.3

Version 3.3.x is built to support Morpheus version 6.3 Standard Release
Version 3.2.x is built to support Morpheus version 6.2 LTS Release

Each Plugin version will specify the Minimum supported Morpheus version and Plugin API version.

### Plugin version 3.3.0 supports minimum Morpheus version 6.3.4 with plugin API 1.0.6
### Plugin version 3.2.0 supports minimum Morpheus version 6.2.7 with plugin API 0.15.10

## Introduction
This is the official Morpheus plugin for interacting with Microsoft DNS. This automates functions as it relates to automatically creating DNS Records and cleaning up DNS records both during workload provisioning and manually. It should be noted that if joining a Windows VM to an Active Directory Domain, this integration is not needed as the Domain joining typically auto creates a DNS record. This was originally embedded into Morpheus and is being extracted for easier maintenance.

## New with v3

### Plugin Integration Controls

- Configure the Dns Integration via the MICROSOFT DNS INTEGRATION dialog. To Add a new integration use Administration -> Integrations  and click + NEW INTEGRATION then select Microsoft DNS from the list.
- To make changes to an existing integration use Administration -> Integrations then click on the Integration NAME link to access the dialog

### MS DNS Integration Dialog Options

- NAME - Enter a name for the Integration
- RPC SERVER - Enter the Name of the server providing access to the Microsoft DNS Services. This is the Server Morpheus will connect to directly. **NOTE** This will also be the DNS Server if accessing the DNS Services directly.
- RPC PORT - (Visible if USE AGENT FOR RPC is unchecked). The WinRm port number 5985/5986. Default is 5985
- USE AGENT FOR RPC checkbox. **NEW** Select this option to have the Plugin use a configured Agent to handle the Morpheus to Windows Rpc connection. The RPC SERVER should be an instance or managed vm and the Morpheus Agent should be configured to Logon As the DNS Service user.
- CREDENTIALS - Provide account credentials for the integration. You may use credentials already stored in Morpheus or create new Username/Password credentials.
- ZONE FILTER was introduced in v2.0 of the plugin. The ZONE FILTER is a comma separated list of glob style filters which can be used to specify the zones that Morpheus will import and sync.
  - Glob style filters apply to the zone name ONLY and at a domain level.
  - The \* character matches any legal Dns character [a-zA-Z0-9_-] 0 or more times.
  - Wildcarding stops at the . (period)
  - Leave blank to import ALL forward and reverse zones
- DNS SERVER - If the RPC SERVER is not the server hosting DNS Services then add the FQDN name of the DNS server here. Leave blank if the RPC SERVER is also the DNS Server.
- SERVICE TYPE - **NEW** (Visible if the DNS SERVER is not blank). This option informs the plugin how the RPC SERVER should contact the DNS SERVER. There are 3 supported options
  - **local** : When the RPC SERVER is the DNS Server (ie when DNS SERVER is blank), local is the default and ONLY option.
  - **wmi** : Use wmi when the RPC SERVER contacts the DNS Server over wmi. This is normally the default option when using and intermediate RPC SERVER
  - **winrm** : Use this option when the RPC SERVER connects to DNS SERVER over a winrm session. Not often used due to WinRm restrictions on Domain Controllers
- INVENTORY EXISTING - Have the integration import and sync all DNS records for the matching Zones. Using this option is not recommended for installations with large namespaces.
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

This plugin includes improvements in error handling and validation. Connectivity and access to DNS Services is tested at the time the integration dialog is saved. The Dialog will not save unless validation is passed successfully. The integration dialog will hint where problems occur but you should check the Morpheus Health logs to see detailed messages. To force the integration to save you can uncheck the ENABLED checkbox. Doing this disables the validation testing allowing you to save the integration dialog contents allowing you to revisit the dialog once any issues have been resolved.

#### Troubleshooting Connections

A new feature of v3 is the ability to run a connection test via the Morpheus Applicance. Users must have full access to Integrations permission to test a Microsoft DNS plugin connection. To test connectivity to Integration with id 5 browse to the following url in Morpheus

https://my.morpheus.appliance/plugin/msdns/service?integrationId=5

The plugin will run a series of tests using details from the Integration dialog. **NOTE** Tests can be run even if the integration ENABLED checkbox is unticked allowing troubleshooting with the integration offline.

Results are output in the browser in json.

```
Morpheus Microsoft DNS Integration Service Profile
Discovered service profile for Microsoft DNS integration : 5
Rpc Connection Status true

Successful rpc response from spie-mo-w-3011 via agent: Command completed successfully

Errors

{
    
}

Rpc Output

{
    "status": 0,
    "cmdOut": {
        "serviceProfile": {
            "rpcHost": "SPIE-MO-W-3011",
            "rpcType": "agent",
            "serviceHost": "ip-c61302.myad.net",
            "serviceType": "wmi",
            "useCachedCredential": false
        },
        "dnsServer": {
            "computerName": "IP-C61302.myad.net",
            "version": "10.0.17763"
        },
        "rpcSession": {
            "userId": "myad\\spsvcdns",
            "computerName": "SPIE-MO-W-3011",
            "authenticationType": "Kerberos",
            "impersonation": "None",
            "isAdmin": true,
            "localProfile": "C:\\Users\\spsvcdns\\AppData\\Local",
            "tokenGroups": [
                "myad\\Domain Users",
                "Everyone",
                "BUILTIN\\Users",
                "BUILTIN\\Administrators",
                "NT AUTHORITY\\SERVICE",
                "CONSOLE LOGON",
                "NT AUTHORITY\\Authenticated Users",
                "NT AUTHORITY\\This Organization",
                "LOCAL",
                "Authentication authority asserted identity",
                "myad\\AWS Delegated Domain Name System Administrators",
                "myad\\AWS Delegated Server Administrators",
                "myad\\AWS Delegated Add Workstations To Domain Users",
                "myad\\DnsAdmins",
                "myad\\AWS Delegated Kerberos Delegation Administrators"
            ],
            "isSystem": false,
            "isService": true,
            "isNetwork": false,
            "isBatch": false,
            "isInteractive": false,
            "isNtlmToken": false
        },
        "serviceSession": {
            "userId": "myad\\spsvcdns",
            "computerName": "SPIE-MO-W-3011",
            "authenticationType": "Kerberos",
            "impersonation": "None",
            "isAdmin": true,
            "localProfile": "C:\\Users\\spsvcdns\\AppData\\Local",
            "tokenGroups": [
                "myad\\Domain Users",
                "Everyone",
                "BUILTIN\\Users",
                "BUILTIN\\Administrators",
                "NT AUTHORITY\\SERVICE",
                "CONSOLE LOGON",
                "NT AUTHORITY\\Authenticated Users",
                "NT AUTHORITY\\This Organization",
                "LOCAL",
                "Authentication authority asserted identity",
                "myad\\AWS Delegated Domain Name System Administrators",
                "myad\\AWS Delegated Server Administrators",
                "myad\\AWS Delegated Add Workstations To Domain Users",
                "myad\\DnsAdmins",
                "myad\\AWS Delegated Kerberos Delegation Administrators"
            ],
            "isSystem": false,
            "isService": true,
            "isNetwork": false,
            "isBatch": false,
            "isInteractive": false,
            "isNtlmToken": false
        },
        "domainSOAServers": {
            "nameToQuery": "ip-c61302.myad.net",
            "fqdn": "ip-c61302.myad.net",
            "dcList": [
                {
                    "zone": "myad.net",
                    "dnsServer": "ip-c61301.myad.net"
                },
                {
                    "zone": "myad.net",
                    "dnsServer": "ip-c61302.myad.net"
                }
            ]
        }
    },
    "errOut": null
}
```


### Custom Powershell Script Module
All Morpheus DNS related Powershell functions are contained in a Powershell script file stored within the plugin. The Powershell script is automatically downloaded to the RPC SERVER and stored in the LocalAppData profile for the service account user. The file contents are md5 checked to ensure the file is not tampered with. The module is refreshed from the plugin if the md5 sum does not match.
The module contains custom functions designed to interface with the MsDns Plugin via json.

- Having the Powershell module installed on the RPC SERVER offers some performance benefits as scripts are no longer transferred on each Rpc call.
- The Powershell Functions test rpc connectivity and DNS service connectivity tests on each sync refresh ensuring the integration is healthy
- The module uses a standard json interface between Windows RPC SERVER and Morpheus
- Parsing DNS resource record properties into json is now much faster.

### Intermediary Server Support

To use an intermediate server:
- enter the fqdn of the intermediate server as the RPC SERVER
- Select/Deselect USE AGENT FOR RPC. If de-selected the RPC transport is WinRM
- enter the fqdn of the Dns Server as DNS SERVER
- Select a SERVICE TYPE from the select list (see descripotion below)


#### Morpheus Agent as RPC Transport
This version allows the plugin to use an intermediate server (the RPC SERVER) with the Morpheus Windows Agent installed as the RPC Transport. The agent would need to be configured to run under a domain service account with access to DNS and so should therefore be dedicated to this purpose. Using the Morpheus Windows Agent as the RPC Transport has a number of advantages. The most significant is that the Morpheus Agent runs with a full Kerberos login allowing delegation to DNS Services on domain controllers without having to enable WinRM. The Agent also offers significant performance improvements over WinRM RPC transport. When using the Agent as the Rpc Transport you will need a Managed Windows Instance joined to the Active Directory Domain where your DNS service is managed. The Windows instance must also have the Microsoft DNS Server Management Powershell module installed (Windows feature RSAT-DNS-Server). The Managed Instance/Server must have the Morpheus Agent configured to logon as a domain account with access to manage DNS.
Enter the fully qualified hostname of the Server Object in the RPC SERVER textbox.  If the server cannot be located with a configured Agent an error message is displayed.

#### WinRM as RPC Transport
WinRM is used as the RPC Transport when the USE AGENT FOR RPC is unchecked. In this scenario Morpheus connects to the RPC SERVER over WinRM. The RPC SERVER must have the Powershell DNS Server Management Tools Installed (Windows feature RSAT-DNS-Server).

#### SERVICE TYPE

When using an Intermediate Server as the RPC SERVER it is crucial to select the correct SERVICE TYPE. The SERVICE TYPE specifies how the RPC SERVER is to connect to the DNS Services, There are 3 options and you must select the correct option for your implementation.

- Local - The DNS Service is Local: ONLY valid if not using and Intermediate Server
- WMI - Use Wmi to access DNS Service (Default) - RPC Server uses WMI to connect to DNS Service.
- WinRm - Start a WinRM session on the DNS Server to access DNS. Not as secure and requires WinRM access to DNS Server

Using SERVICE TYPE **Wmi** is the default and recommended method when using an intermediate server. For Wmi the service account will require access to the Microsoft DNS WMI namespace on the DNS Server and in most cases the intermediate windows server Computer Account must be trusted for delegation in Active Directory Users and Computer to allow Kerberos access to any service unless you know the specific Service Principal Names for your environment **NOTE** that if the Morpheus Agent is used as Rpc Transport and the agent logs in with the service credentials then delegation of the Computer Account will not normally be required as the service runs in much the same way as an interactive login.

Using SERVICE TYPE **WinRm** the Intermediate server opens a PS Remoting session to the DNS Server using cached credentials to re-authenticate and obtain a Kerberos session. Invoke-Command is used with the cached credentials to access the DNS Services and return results.

### DNS Record validation and Error Handling

- DNS records are now fully validated before they are created. Only record types A, AAAA, CNAME and PTR are currently supported.
- Adding a DNS Record which already exists (ie fqdn and IPAddress match an existing record in DNS) would normally return an error (code 9711) - this is masked to a success to prevent Morpheus aborting the provision.
- Removing a DNS Record that does not exist in DNS (error 9714) is also masked to success to have Morpheus delete its copy
- If a fwd record is created but the PTR record fails (due to missing PTR zone error 9715). This is also masked to success to prevent Morpheus aborting the Provision
- All error are logged to the Morpheus Health logs.

### AWS Directory Services Support

Support AWS Active Directory service.

- Access is only possible via a correctly configured intermediate server (RPC SERVER) hosted in AWS and having the DNS Management Tools installed.
- The DNS SERVER must be the fully qualified name of one of the AWS Domain controllers.
- The Service Account should be a member of AWS Delegated Domain Name System Administrators, AWS Delegated Kerberos Delegation Administrators and AWS Delegated Server Administrators (for access to RPC SERVER).
- The RPC SERVER computer object should be trusted for delegation for all Kerberos Services on the AWS Directory Service domain controllers. This can be performed using AD Users and Computers to modify the properties of the RPC SERVER Computer object. Right click the computer object, select properties and open the Delegation tab. Select the Radio button **Trust this computer for delegation to any service (Kerberos Only). Click OK to Save

Note it is possible to finely tune the delegation so that the RPC SERVER computer object can only delegate to specific services if this is required.