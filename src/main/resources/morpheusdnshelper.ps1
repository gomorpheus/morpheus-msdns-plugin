Add-Type -AssemblyName "System.Security"

Function ConvertTo-ProtectedString {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [String]$Secret,
        [ValidateSet("LocalMachine","CurrentUser")]
        [String]$Scope="LocalMachine",
        [Byte[]]$Salt=$Null
    )

    Process {
        try {
            $bytesToEncrypt = [Convert]::FromBase64String($Secret)
            if ($Scope -eq "LocalMachine") {
                $uid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $Salt = [Byte[]]::new($uid.BinaryLength)
                $uid.GetBinaryForm($Salt,0)
                $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytesToEncrypt,$Salt,[System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            } else {
                $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytesToEncrypt,$Salt,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            }
            return [System.Convert]::ToBase64String($encryptedBytes)
        }
        catch {
            throw $_
            return $Null
        }
    }
}

Function ConvertFrom-ProtectedString {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [String]$ProtectedString,
        [ValidateSet("LocalMachine","CurrentUser")]
        [String]$Scope="LocalMachine",
        [Byte[]]$Salt=$Null
    )
    Process{
        $rtn = [PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
        $bytesToDecrypt = [System.Convert]::FromBase64String($ProtectedString)
        try {
            if ($Scope -eq "LocalMachine") {
                $uid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $Salt = [Byte[]]::new($uid.BinaryLength)
                $uid.GetBinaryForm($Salt,0)
                $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytesToDecrypt,$Salt,[System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            } else {
                $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytesToDecrypt,$Salt,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            }
            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }
        catch {
            throw $_
            return $Null
        }
    }
}

Function Get-AuthoritativeServers {
    [CmdletBinding()]
    param (
        [String]$Name=[Environment]::MachineName
    )

    $rtn = [PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
    if (($Name -Split "\.").Count -eq 1) {
        # Name should be an fqdn - if not try looking it up - exit if no FQDN found
        try {
                $lookup = Resolve-DnsName -Name $Name -ErrorAction Stop | Select-Object -First 1
                $fqdn = $lookup.name
        }
        catch {
            $rtn.status = 1
            $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            return $rtn
        }
    } else {
        # Name already looks like an FQDN
        $fqdn = $Name
    }
    try {
        $SOA = Resolve-DnsName -Name $fqdn -Type SOA -ErrorAction Stop | Where-Object {$_.Type -eq "SOA"}
        if ($SOA) {
            #lookup SVR records for AD Domain Controller Dns
            $SRVRecordName = "_ldap._tcp.dc._msdcs.{0}" -F $SOA.Name
            #Possible lookup Name servers
            $DCList = Resolve-DnsName -Name $SRVRecordName -DnsOnly -Type SRV -ErrorAction Stop | Where-Object {$_.Type -eq "SRV"}
            if ($DCList) {
                $rtn.cmdOut = [PSCustomObject]@{
                    nameToQuery=$Name;
                    fqdn=$fqdn;
                    dcList = $DCList | Foreach-Object {[PSCustomObject]@{zone=$SOA.Name;dnsServer=$_.NameTarget}}
                }
            }
        }
    }
    catch {
        $rtn.status = 1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn
}

#Pipeline Function to get Dns Zones
Function Out-DnsZoneRecord {

    param (
        [Parameter(ValueFromPipeline=$true)]$DnsRec
    )

    begin {
        $Out = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    process {
        foreach ($rec in $dnsRec) {
            $dnsout = [PSCustomObject]@{
                zoneName = $rec.ZoneName;
                zoneType = $rec.ZoneType;
                isAutoCreated = $rec.IsAutoCreated;
                isDsIntegrated = $rec.IsDsIntegrated;
                isReverseLookupZone = $rec.IsReverseLookupZone;
                isSigned = $rec.IsSigned
            }
            $Out.Add($dnsOut)
        }
    }
    end {
        # always return an array
        return ,$Out
    }
}

#Pipeline Function to get RecordData properties from DnsServerResourceRecord for known RRTypes
Function Out-DnsResourceRecord {

param (
    [Parameter(ValueFromPipeline=$true)]$DnsRec
)

    begin {
        $Out = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    process {
        foreach ($rec in $dnsRec) {
            $dnsout = [PSCustomObject]@{
                hostName=$rec.HostName;
                distinguishedName=$rec.DistinguishedName;
                recordType=$rec.RecordType;
                timeToLive=$rec.TimeToLive.TotalSeconds;
                recordData=""
            }
            switch ($rec.RecordType) {
                "A" {$dnsout.recordData = $rec.RecordData.IPv4address.ToString()}
                "AAAA" {$dnsout.recordData = $rec.RecordData.IPv6address.ToString()}
                "AFSDB" {$dnsout.recordData = "[" + $rec.RecordData.SubType + "][" + $rec.RecordData.ServerName + "]"}
                "ATMA" {$dnsout.recordData = "[" + $rec.RecordData.AddressType + "][" + $rec.RecordData.Address + "]"}
                "DHCID" {$dnsout.recordData = $rec.RecordData.DHCID}
                "CNAME" {$dnsout.recordData = $rec.RecordData.HostNameAlias}
                "DNAME" {$dnsout.recordData = $rec.RecordData.DomainNameAlias}
                "HINFO" {$dnsout.recordData = "[" + $rec.RecordData.Cpu + "][" + $rec.RecordData.OperatingSystem + "]"}
                "ISDN" {$dnsout.recordData = "[" + $rec.RecordData.IsdnNumber + "][" + $rec.RecordData.IsdnSubAddress + "]"}
                "MX" {$dnsout.recordData =  "[" + $rec.RecordData.Preference + "][" + $rec.RecordData.MailExchange + "]"}
                "NS" {$dnsout.recordData = $rec.RecordData.NameServer}
                "PTR" {$dnsout.recordData = $rec.RecordData.PtrDomainName}
                "RP" {$dnsout.recordData = "[" + $rec.RecordData.ResponsiblePerson + "][" + $rec.RecordData.Description + "]"}
                "RT" {$dnsout.recordData = "[" + $rec.RecordData.Preference + "][" + $rec.RecordData.IntermediateHost + "]"}
                "SOA" {$dnsout.recordData = "[" + $rec.RecordData.SerialNumber + "][" + $rec.RecordData.PrimaryServer + "][" + $rec.RecordData.ResponsiblePerson + "][" + $rec.RecordData.ExpireLimit + "][" + $rec.RecordData.MinimumTimetoLive + "][" + $rec.RecordData.RefreshInterval + "][" + $rec.RecordData.RetryDelay + "]"}
                "SRV" {$dnsout.recordData = "[" + $rec.RecordData.Priority + "][" + $rec.RecordData.Weight + "][" + $rec.RecordData.Port + "][" + $rec.RecordData.DomainName + "]"}
                "TXT" {$dnsout.recordData = $rec.RecordData.DescriptiveText}
                "WINS" {$dnsout.recordData = "[" + $rec.RecordData.Replicate + "][" + $rec.RecordData.LookupTimeout + "][" + $rec.RecordData.CacheTimeout + "][" + $rec.RecordData.WinsServers + "]"}
                "WINSR" {$dnsout.recordData = "[" + $rec.RecordData.Replicate + "][" + $rec.RecordData.LookupTimeout + "][" + $rec.RecordData.CacheTimeout + "][" + $rec.RecordData.ResultDomain + "]"}
                "WKS" {$dnsout.recordData = "[" + $rec.RecordData.InternetProtocol + "][" + $rec.RecordData.Service + "][" + $rec.RecordData.InternetAddress + "]"}
                "X25" {$dnsout.recordData = $rec.RecordData.PSDNAddress}
                "DNSKEY" {$dnsout.recordData = "DNSKey unsupported"}
                "DS" {$dnsout.recordData = "[" + $rec.RecordData.KeyTag + "][" + $rec.RecordData.CryptoAlgorithm + "][" + $rec.RecordData.DigestType + "][" + $rec.RecordData.Digest + "]"}
                "NSEC" {$dnsout.recordData = "[" + $rec.RecordData.Name + "][" + $rec.RecordData.CoveredRecordTypes + "]"}
                "NSEC3" {$dnsout.recordData = "[" + $rec.RecordData.HashAlgorithm + "][" + $rec.RecordData.OptOut + "][" + $rec.RecordData.Iterations + "][" + $rec.RecordData.Salt + "][" + $rec.RecordData.NextHashedOwnerName + "][" + $rec.RecordData.CoveredRecordTypes + "]"}
                "NSEC3PARAM" {$dnsout.recordData = "[" + $rec.RecordData.HashAlgorithm + "][" + $rec.RecordData.Iterations + "][" + $rec.RecordData.Salt + "]"}
                "RRSIG" {$dnsout.recordData = "[" + $rec.RecordData.TypeCovered + "][" + $rec.RecordData.CryptoAlgorithm + "][" + $rec.RecordData.KeyTag + "]["+ $rec.RecordData.LabelCount + "]["  + $rec.RecordData.NameSigner + "][" + "SignatureInception: " + $rec.RecordData.SignatureInception + "][" + "SignatureExpiration: " + $rec.RecordData.SignatureExpiration + "][" + $rec.RecordData.OriginalTtl + "][" + $rec.RecordData.Signature + "]"}
                default {$dnsout.recordData =  "unsupported rType $($Rec.RecordType)"}
        }
            $Out.Add($dnsOut)
        }
    }
    end {
        # always return an array
        return ,$Out
    }
}

Function Export-MorpheusCredential {
    [CmdletBinding()]
    param(
        [String]$Password
    )

    $rtn=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $username = $WinId.Name
    $cacheName = "{0}-dnsPlugin.ss" -F $winId.User.Value
    $cacheFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath $cacheName
    try {
        $encryptedString = ConvertTo-ProtectedString -Secret $Password -ErrorAction Stop
        $encryptedString | Set-Content -Path $cacheFile -Force -ErrorAction Stop
        $rtn.cmdOut = [PSCustomObject]@{encryptedString = $encryptedString}
    }
    catch {
        $rtn.status = 2
        $rtn.errOut = [PSCustomObject]@{message="Error creating cache file {0} - {1}" -F $cacheFile,$_.Exception.Message}
    }
    if ($rtn.status -eq 0) {
        try {
            $secret = Get-Content -Path $cacheFile -Raw -ErrorAction Stop
            $secString = ConvertTo-SecureString -AsPlainText (ConvertFrom-ProtectedString -ProtectedString $secret) -Force -ErrorAction Stop
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $secString) -ErrorAction Stop
            $cred = $Null
        }
        catch {
            $rtn.status = 1
            $rtn.errOut = [PSCustomObject]@{message="Error creating Credential from SecureString - exception:  {0}" -F $_.Exception.Message}
        }
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Import-MorpheusCredential {
    $rtn = [PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
    $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $username = $WinId.Name
    $cacheName = "{0}-dnsPlugin.ss" -F $winId.User.Value
    $cacheFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath $CacheName
    if (Test-Path -Path $cacheFile) {
        try {
            $secret = Get-Content -Path $cacheFile -Raw -ErrorAction Stop
            $secString = ConvertTo-SecureString -AsPlainText (ConvertFrom-ProtectedString -ProtectedString $secret) -Force -ErrorAction Stop
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $secString) -ErrorAction Stop
            $rtn.cmdOut = [PSCustomObject]@{cred = $cred}
        }
        catch {
            $rtn.status = 1
            $rtn.errOut = [PSCustomObject]@{message="Cannot decrypt secure credentials from cache. Exception: {0}" -F $_.Exception.Message}
        }
    } else {
        $rtn.status=2
        $rtn.errOut = [PSCustomObject]@{message="Cannot find credential cache file {0}" -F $cacheFile}
    }
    return $rtn
}

Function Get-RpcSessionInfo {
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    try {
        $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]$winId
        $tokenGroups = $winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
        $isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $rtn.cmdOut = [PSCustomObject]@{
            userId=$winId.Name;
            computerName=[Environment]::MachineName;
            authenticationType=$winId.AuthenticationType;
            impersonation = $winId.ImpersonationLevel.ToString();
            isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
            tokenGroups=$tokenGroups;
            isSystem=$winId.isSystem;
            isService=$tokenGroups -contains "NT AUTHORITY\SERVICE";
            isNetwork=$tokenGroups -contains "NT AUTHORITY\NETWORK";
            isBatch=$tokenGroups -contains "NT AUTHORITY\BATCH";
            isInteractive=$tokenGroups -contains "NT AUTHORITY\INTERACTIVE";
            isNtlmToken=$tokenGroups -contains "NT AUTHORITY\NTLM Authentication"
        }
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message="Error while querying session details. Exception: {0}" -F $_.Exception.Message}
    }
    return $rtn
}

Function Test-DnsServicePath {
    [CmdletBinding()]
    param(
        [String]$ServiceHost=$Null,
        [ValidateSet("winrm","wmi","local")]
        [String]$ServiceType="wmi",
        [Switch]$UseCachedCredential,
        [ValidateSet("winrm","agent","scheduletask","unknown")]
        [String]$RpcType="unknown"
    )

    #ScriptBlock for performing the Service Tests via Invoke-Command
    $testBlock={
        param($Computer=$Null)

        # Declare the response PSCustomObject properties
        $ret = [PSCustomObject]@{
            status=0;
            cmdOut=[PSCustomObject]@{
                serviceProfile=$Null;
                dnsServer=$Null;
                rpcSession=$Null;
                serviceSession=$Null;
                domainSOAServers=$Null
            };
            errOut=$Null
        }
        $dnsParams = @{ErrorAction="Stop"}

        if($Computer) {
            $dnsParams.Add("ComputerName",$Computer)
        }
        #return session info
        $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]$winId
        $tokenGroups = $winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
        $isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $ret.cmdOut.serviceSession = [PSCustomObject]@{
            userId=$winId.Name;
            computerName=[Environment]::MachineName;
            authenticationType=$winId.AuthenticationType;
            impersonation = $winId.ImpersonationLevel.ToString();
            isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
            tokenGroups=$tokenGroups;
            isSystem=$winId.isSystem;
            isService=$tokenGroups -contains "NT AUTHORITY\SERVICE";
            isNetwork=$tokenGroups -contains "NT AUTHORITY\NETWORK";
            isBatch=$tokenGroups -contains "NT AUTHORITY\BATCH";
            isInteractive=$tokenGroups -contains "NT AUTHORITY\INTERACTIVE";
            isNtlmToken=$tokenGroups -contains "NT AUTHORITY\NTLM Authentication";
        }
        try {
            #Test DNS Access - use splatting
            $ret.cmdOut.dnsServer = Get-DnsServerSetting @dnsParams | Select-Object -Property computerName, @{n="version";e={"{0}.{1}.{2}" -f $_.MajorVersion,$_.MinorVersion,$_.BuildNumber}}
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        $ret
    } #End $testBlock

    # key details on how services are accessed
    $serviceProfile = [PSCustomObject]@{
        rpcHost=$Null;                # Morpheus connects to the rpcHost
        rpcType=$RpcType;             # how Morpheus is connecting
        serviceHost=$Null;            # DNS Services host - may be same as rpcHost (usually a Domain Controller)
        serviceType=$Null;            # wmi, winrm or local
        useCachedCredential=$false    # Use credentials to upgrade to Kerberos login
    }

    $testParams = @{
        ErrorAction="Stop";
        ScriptBlock=$testBlock
    }
    if ($ServiceHost) {
        if ($ServiceType -eq "local") {$ServiceType = "wmi"}
        #Using Jump Server serviceType cant be local
        switch ($ServiceType) {
            "winrm" {
                $testParams.Add("ComputerName",$ServiceHost)
                $serviceProfile.rpcHost=$ServiceHost
                $serviceProfile.serviceHost=$ServiceHost
                $serviceProfile.serviceType = "winrm"
                break
            }
            "wmi" {
                $TestParams.Add("ArgumentList",$ServiceHost)
                $serviceProfile.rpcHost=[Environment]::MachineName
                $serviceProfile.serviceHost=$ServiceHost
                $serviceProfile.serviceType = "wmi"
                break
            }
        }
    } else {
        #Local dnsService
        $serviceProfile.rpcHost=[Environment]::MachineName
        $serviceProfile.serviceHost=[Environment]::MachineName
        $serviceProfile.serviceType = "local"
    }
    # Does this test require re-authentication with cached credentials?
    if ($UseCachedCredential) {
        $serviceProfile.useCachedCredential = $true
        $cred = Import-MorpheusCredential
        if ($cred.status -gt 0) {
            #Cant load credential - exit now
            return $cred
        }
        $testParams.Add("Credential",$cred.cmdOut.cred)
        #when using credentials ComputerName must also be specified even if its local machine name
        if (-Not $testParams.ContainsKey("ComputerName")) {$testParams.Add("ComputerName",[Environment]::MachineName)}
    }
    #Perform test via Invoke-Command parameter splatting
    try {
        $rtn = Invoke-Command @testParams
    }
    catch {
        #Catch any error with the Invoke-Command
        $rtn.status = 1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    finally {
        #Add the serviceProfile to cmdOut
        $rtn.cmdOut.serviceProfile = $serviceProfile
    }
    return $rtn
}


#Test the connection path to the DNS Services and return details.
#The rtn.cmdOut is a PSCustomObject containing the results which are then used by the plugin for servicing DNS
Function Test-MorpheusServicePath {
    [CmdletBinding()]
    param(
        [Alias("Computer")]
        [String]$ServiceHost=$Null,
        [ValidateSet("winrm","wmi","local")]
        [String]$ServiceType
    )

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    if (!$ServiceType) {
        $ServiceType = if ($ServiceHost) {"wmi"} else {"local"}
    }
    #rpcInfo - how is Morpheus connecting?
    $rpcInfo = Get-RpcSessionInfo
    if ($rpcInfo.status -gt 0) {
        return $rpcInfo
    }
    if ($rpcInfo.cmdOut.isNetwork) {
        $rpcType = "winrm"
    } elseif ($rpcInfo.cmdOut.isService) {
        $rpcType = "agent"
    } elseif ($rpcInfo.cmdOut.isBatch) {
        $rpcType = "scheduletask"
    } else {
        $rpcType = "unknown"
    }
    # initial parameters - useCachedCredential if rpcSession is Network NTLM
    $testParams = @{
        ErrorAction="Stop";
        UseCachedCredential=($rpcInfo.cmdOut.isNetwork -And ($rpcInfo.cmdOut.isNtlmToken -Or $rpcInfo.cmdOut.authenticationType -eq "NTLM"));
        RpcType=$rpcType
    }
    if ($ServiceHost) {
        $testParams.Add("ServiceHost",$ServiceHost)
        $soaServers = Get-AuthoritativeServers -Name $ServiceHost
        #ServiceHost is remote: ServiceType cannot be local and must be wmi or winrm - default is wmi
        if ($ServiceType -eq "local") {$ServiceType = "wmi"}
    } else {
        #Null ServiceHost - only test local service
        $ServiceType = "local"
        $soaServers = Get-AuthoritativeServers
    }
    $testParams.Add("ServiceType",$ServiceType)
    # Run Test
    $rtn = Test-DnsServicePath @testParams
    # Add DomainSOAServers to the response
    $rtn.cmdOut.domainSOAServers = $soaServers.cmdOut
    # Add the original Morpheus initiated rpcSession to the return object
    $rtn.cmdOut.rpcSession = $rpcInfo.cmdOut
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Add-MorpheusDnsRecord {
    [CmdletBinding()]
    param(
        [String]$RrType,
        [String]$Name,
        [String]$Zone,
        [String]$Data,
        [Int]$Ttl=86400,
        [Switch]$CreatePtr,
        [String]$Computer=$Null,
        [ValidateSet("local","winrm","wmi")]
        [String]$ServiceType="local"
    )

    $addBlock = {
        param($rrType,$name,$zone,$data,$ttl,$createPtr,$serviceHost=$null)
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
        $ts = New-TimeSpan -seconds $ttl
        switch ($rrType) {
            "A"     {$dataPropertyName="IpV4Address"; $rTypeParameterName="A"; $supportsCreatePtr=$True}
            "AAAA"  {$dataPropertyName="IpV6Address"; $rTypeParameterName="AAAA"; $supportsCreatePtr=$True}
            "CNAME" {$dataPropertyName="HostNameAlias"; $rTypeParameterName="CNAME"; $supportsCreatePtr=$False}
            "PTR"   {$dataPropertyName="PtrDomainName"; $rTypeParameterName="PTR"; $supportsCreatePtr=$False}
            default {$ret.status=1;$ret.ErrOut=[PSCustomObject]@{message="Resource Record type $($rrType) not supported by this plugin"}}
        }

        #use parameter splatting for DNS CmdLets
        $getparams = @{
            Name=$name;
            ZoneName=$zone;
            RRType=$rrType;
            ErrorAction="Stop"
        }
        $addparams = @{
            Name=$name;
            ZoneName=$zone;
            $rTypeParameterName=$True;
            TimeToLive=$ts;
            $dataPropertyName=$data;
            AllowUpdateAny=$True;
            ErrorAction="Stop"
        }
        if ($serviceHost) {
            $getparams.Add("ComputerName",$serviceHost)
            $addparams.Add("ComputerName",$serviceHost)
        }
        if ($supportsCreatePtr) {
            $addparams.Add("CreatePtr",$createPtr)
        }
        # Prevent issues creating record by testing if it exists first
        try {
            $existingRecord = Get-DnsServerResourceRecord @getparams | Where-Object {$_.RecordData.$dataPropertyName -eq $data}
            if ($existingRecord) {
               $ret.cmdOut = $existingRecord
               $ret.status = 9711
               $ret.errOut = [PSCustomObject]@{message="A matching DNS Record already exists"}
               $exists = $true
            } else {
               $exists = $false
            }
        }
        catch {
            $exists = $false
        }
        # return existing record
        if ($exists) {return $ret}
        # otherwise try adding
        try {
            $ret.cmdOut = Add-DnsServerResourceRecord @addparams
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        finally {
            # Check DNS for matching record and return Data. Retain any error messages
            try {
                $ret.cmdOut = Get-DnsServerResourceRecord @getparams | Where-Object {$_.RecordData.$dataPropertyName -eq $data}
            }
            catch {
                $ret.cmdOut = $Null
            }
        }
        $ret
    } #End of ScriptBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $params = @{
        ScriptBlock=$addBlock;
        ErrorAction="Stop";
        ArgumentList=@($RrType,$Name,$Zone,$Data,$Ttl,$CreatePtr)
    }

    if ($Computer) {
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            $params.Add("Credential",$cred.cmdOut.cred)
            $params.Add("ComputerName",$Computer)
            if ($ServiceType -eq "wmi") {
                $params.ComputerName = [Environment]::MachineName
                $params.ArgumentList = @($RrType,$Name,$Zone,$Data,$Ttl,$CreatePtr,$Computer)
            }
        } else {
            #Failed to load cached credential
            return $cred | ConvertTo-Json -Depth 5 -Compress
        }
    }
    try {
        $rtn = Invoke-Command @params
        $rtn.cmdOut = $rtn.cmdOut | Out-DnsResourceRecord
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Remove-MorpheusDnsRecord {
    [CmdletBinding()]
    param (
        [String]$RrType,
        [String]$Name,
        [String]$Zone,
        [String]$Data,
        [String]$Computer=$Null,
        [ValidateSet("local","winrm","wmi")]
        [String]$ServiceType="local"
    )
    # Start of ScriptBlock
    $removeBlock = {
        param($rrType,$name,$zone,$data,$serviceHost=$Null)
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
        switch ($rrType) {
            "A"     {$dataPropertyName="IpV4Address"}
            "AAAA"  {$dataPropertyName="IpV6Address"}
            "CNAME" {$dataPropertyName="HostNameAlias"}
            "PTR"   {$dataPropertyName="PtrDomainName"}
            default {
               $ret.status=1;
               $ret.errOut=[PSCustomObject]@{message="Resource Record type $($rrType) not supported by this plugin"}
               return $ret
            }
        }
        #use parameter splatting for DNS CmdLets
        $getparams = @{
            Name=$name;
            ZoneName=$zone;
            RRType=$rrType;
            ErrorAction="Stop"
        }
        $removeparams = @{
            RRType=$rrType;
            Name=$name;
            ZoneName=$zone;
            RecordData=$data;
            Force=$true;
            ErrorAction="Stop"
        }
        if ($serviceHost) {
            $getparams.Add("ComputerName",$serviceHost)
            $removeparams.Add("ComputerName",$serviceHost)
        }
        try {
           $recordToRemove = Get-DnsServerResourceRecord @getparams | Where-Object {$_.RecordData.$dataPropertyName -eq $data}
           if ($recordToRemove) {
              $response = Remove-DnsServerResourceRecord @removeparams
           } else {
              $ret.status = 9714
              $ret.errOut = [PSCustomObject]@{message="No matching DNS record exists"}
           }
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        finally {
            if ($recordToRemove) {
               $ret.cmdOut = $recordToRemove
            }
        }
        $ret
    } # End of ScriptBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $params = @{
        ScriptBlock=$removeBlock;
        ArgumentList=@($RrType,$Name,$Zone,$Data);
        ErrorAction="Stop"
    }
    if ($Computer) {
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            $params.Add("Credential",$cred.cmdOut.cred)
            $params.Add("ComputerName",$Computer)
            if ($ServiceType -eq "wmi") {
                $params.ComputerName = [Environment]::MachineName
                $params.ArgumentList = @($RrType,$Name,$Zone,$Data,$Computer)
            }
        } else {
            #Failed to load cached credential
            return $cred | ConvertTo-Json -Depth 5 -Compress
        }
    }
    try {
        $rtn = Invoke-Command @params
        $rtn.cmdOut = $rtn.cmdOut | Out-DnsResourceRecord
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Get-MorpheusDnsZone {
    [CmdletBinding()]
    param(
        [String]$Computer=$Null,
        [ValidateSet("local","winrm","wmi")][String]$ServiceType="local"
    )

    $GetZoneBlock = {
        param($serviceHost=$Null)
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
        $params=@{ErrorAction="Stop"}
        if ($serviceHost) {
            $params.Add("ComputerName",$serviceHost)
        }
        try {
            $ret.cmdOut=Get-DnsServerZone @params
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        $ret
    }
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $params = @{ScriptBlock=$GetZoneBlock;ErrorAction="Stop"}
    if ($Computer) {
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            $params.Add("Credential",$cred.cmdOut.cred)
            $params.Add("ComputerName",$Computer)
            if ($ServiceType -eq "wmi") {
                $params.ComputerName = [Environment]::MachineName
                $params.ArgumentList = $Computer
            }
        } else {
            # Failed to load cached credential
            return $cred | ConvertTo-Json -Depth 5 -Compress
        }
    }
    try {
        $rtn = Invoke-Command @params
        $rtn.cmdOut = $rtn.cmdOut | Out-DnsZoneRecord
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Get-MorpheusDnsResourceRecord {
    [CmdletBinding()]
    param(
        [String]$Zone,
        [String]$Computer=$Null,
        [ValidateSet("local","winrm","wmi")][String]$ServiceType="local"
    )

    $GetZoneRecordBlock = {
        param($zone,$serviceHost=$null)
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
        $params=@{
            ZoneName=$zone;
            ErrorAction="Stop"
        }
        if ($serviceHost) {
            $params.Add("ComputerName",$serviceHost)
        }
        try {
            $ret.cmdOut=Get-DnsServerResourceRecord @params
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        $ret
    }
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $params = @{ScriptBlock=$GetZoneRecordBlock;ArgumentList=$Zone;ErrorAction="Stop"}
    if ($Computer) {
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            $params.Add("Credential",$cred.cmdOut.cred)
            $params.Add("ComputerName",$Computer)
            if ($ServiceType -eq "wmi") {
                $params.ComputerName = [Environment]::MachineName
                $params.ArgumentList = @($Zone,$Computer)
            }
        } else {
            # Failed to load cached credential
            return $cred | ConvertTo-Json -Depth 5 -Compress
        }
    }
    try {
        $rtn = Invoke-Command @params
        $rtn.cmdOut = $rtn.cmdOut | Out-DnsResourceRecord
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}

Function Find-MorpheusDnsResourceRecord {
    [CmdletBinding()]
    param(
        [String]$RrType="A",
        [String]$Name=$Null,
        [String]$Zone,
        [String]$Data=$Null,
        [String]$Computer=$Null,
        [ValidateSet("local","winrm","wmi")][String]$ServiceType="local"
    )
    # ScriptBlock
    $findRecordBlock = {
        param($rrType,$name,$zone,$data,$serviceHost=$null)
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
        switch ($rrType) {
            "A"     {$dataPropertyName="IpV4Address"}
            "AAAA"  {$dataPropertyName="IpV6Address"}
            "CNAME" {$dataPropertyName="HostNameAlias"}
            "PTR"   {$dataPropertyName="PtrDomainName"}
            default {
               $ret.status=1;
               $ret.errOut=[PSCustomObject]@{message="Resource Record type $($rrType) not supported by this plugin"}
               return $ret
            }
        }
        $getparams = @{
            ZoneName=$zone;
            RRType=$rrType;
            ErrorAction="Stop"
        }
        if ($serviceHost) {
            $getparams.Add("ComputerName",$serviceHost)
        }
        if ($name) {
            $getparams.Add("Name",$name)
        }

        try {
            if ($data) {
                $ret.cmdOut=Get-DnsServerResourceRecord @getparams | Where-Object {$_.RecordData.$dataPropertyName -eq $data} | Format-List | Out-String -width 512
            } else {
                $ret.cmdOut=Get-DnsServerResourceRecord @getparams
            }
        }
        catch {
            if ($_.Exception.ErrorData) {
                $ret.status = $_.Exception.ErrorData.error_Code
                $ret.errOut = $_.Exception.ErrorData | Select-Object -Property errorSource,message, error_Category,error_Code, error_WindowsErrorMessage
            } else {
                $ret.status = 1
                $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }
        }
        $ret
    } # End of ScriptBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $params = @{
        ScriptBlock=$findRecordBlock;
        ArgumentList=@($RrType,$Name,$Zone,$Data);
        ErrorAction="Stop"
    }
    if ($Computer) {
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            $params.Add("Credential",$cred.cmdOut.cred)
            $params.Add("ComputerName",$Computer)
            if ($ServiceType -eq "wmi") {
                $params.ComputerName = [Environment]::MachineName
                $params.ArgumentList = @($RrType,$Name,$Zone,$Data,$Computer)
            }
        } else {
            # Failed to load cached credential
            return $cred | ConvertTo-Json -Depth 5 -Compress
        }
    }
    try {
        $rtn = Invoke-Command @params
        $rtn.cmdOut = $rtn.cmdOut | Out-DnsResourceRecord
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn | ConvertTo-Json -Depth 5 -Compress
}
