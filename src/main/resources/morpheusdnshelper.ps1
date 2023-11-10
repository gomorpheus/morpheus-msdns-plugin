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

# Helper function to format DNS Output from Format-List into [PSCustomObject[]] 
Function Parse-DnsResponse {
    [CmdLetBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [String]$DnsOutput
    )

    begin {
        $keyValuePattern = "^\s*([A-Za-z_.-]*)\s*:\s*(.*)$"
        $list =[System.Collections.Generic.List[PSCustomObject]]::new()
        $keyList = [Ordered]@{}
    }

    process {
        Foreach ($line in ($DnsOutput -split "\r\n")) {
            if ($line -match $keyValuePattern) {
                $key = $Matches[1].Substring(0,1).ToLower() + $Matches[1].Remove(0,1)
                $value = $Matches[2]
                if ($keyList.Contains($key)) {
                    $dnsRecord = [PSCustomObject]$keyList
                    $list.Add($DnsRecord)
                    $keyList = [Ordered]@{$key=$value}
                } else {
                    $keyList.Add($key,$value)
                }
            }
        }
        # Flush Final record
        if ($keyList.count -gt 0) {
            $dnsRecord = [PSCustomObject]$keylist
            $list.Add($dnsRecord)
        }
        # force array to be returned
        return ,$list
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

Function Test-LocalServicePath {
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]$winId
    $groups=$winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
    $rtn.cmdOut = [PSCustomObject]@{
        userId=$winId.Name;
        authenticationType=$winId.AuthenticationType;
        impersonation = $winId.ImpersonationLevel.ToString();
        isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
        inGroups=$groups;
        serviceType=$Null;
        dnsServer=$Null;
        domainSOAServers=$Null
    }            
    try {
        $rtn.cmdOut.dnsServer = Get-DnsServerSetting -ErrorAction Stop | Select-Object -Property computerName, @{n="version";e={"{0}.{1}.{2}" -f $_.MajorVersion,$_.MinorVersion,$_.BuildNumber}}
        $rtn.cmdOut.serviceType = "local"
    }                
    catch {
        $rtn.status = 1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn 
}

Function Test-WinRmServicePath {
    [CmdletBinding()]
    param(
        $Computer=$null
    )
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    if ($Computer) {
        try {
            $winRmTest = Test-WSMan -ComputerName $Computer -ErrorAction Stop
            $rtn.cmdOut = [PSCustomObject]@{productVersion=$winRmTest.ProductVersion}
        }
        catch {
            $rtn.status = 1
            $rtn.errOut = [PSCustomObject]@{message="Error: No winRm connection to servicePath {0} - exception:  {1}" -F $Computer,$_.Exception.Message}
            return $rtn
        }
        $cred = Import-MorpheusCredential
        if ($cred.status -eq 0) {
            #ScriptBlock
            $sb = {
                $ret = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = [System.Security.Principal.WindowsPrincipal]$winId
                $groups=$winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
                $ret.cmdOut = [PSCustomObject]@{
                    userId=$winId.Name;
                    authenticationType=$winId.AuthenticationType;
                    impersonation = $winId.ImpersonationLevel.ToString();
                    isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
                    inGroups=$groups;
                    serviceType=$Null;
                    dnsServer=$Null;
                    domainSOAServers=$Null
                }                        
                try {
                    $ret.cmdOut.dnsServer = Get-DnsServerSetting -ErrorAction Stop | Select-Object -Property computerName, @{n="version";e={"{0}.{1}.{2}" -f $_.MajorVersion,$_.MinorVersion,$_.BuildNumber}}
                    $ret.cmdOut.serviceType = "winrm"
                }                
                catch {
                    $ret.status = 1
                    $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
                }
                $ret
            } #End of ScriptBlock
            $cachedCreds=$cred.cmdOut.cred
            $params = @{
                ScriptBlock=$sb;
                ComputerName=$Computer;
                Credential=$cachedCreds;
                ErrorAction="Stop"
            }
            try {
                $rtn = Invoke-Command @params
            }
            catch {
                $rtn.status=1
                $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            } 
        } else {
            # Cannot access cached Credentials
            return $cred
        }
    } else {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message="You must supply the servicePath as -Computer parameter"}                
    }
    $rtn 
}

Function Test-WmiServicePath {
    [CmdletBinding()]
    param(
        $Computer=$null
    )
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    if ($computer) {
        $cred = Import-MorpheusCredential
        if ($rtn.status -eq 0) {
            $cachedCreds=$cred.cmdOut.cred
            $sb = {
                param($computer)
                $ret = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
                $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = [System.Security.Principal.WindowsPrincipal]$winId
                $groups=$winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).ToString()}
                $ret.cmdOut = [PSCustomObject]@{
                    userId=$winId.Name;
                    authenticationType=$winId.AuthenticationType;
                    impersonation = $winId.ImpersonationLevel.ToString();
                    isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
                    inGroups=$groups;
                    serviceType=$Null;
                    dnsServer=$Null;
                    domainSOAServers=$Null
                }
                try {
                    #wmi connection to remote Dns Service over RPC
                    $ret.cmdOut.dnsServer = Get-DnsServerSetting -ComputerName $computer -ErrorAction Stop | Select-Object -Property computerName, @{n="version";e={"{0}.{1}.{2}" -f $_.MajorVersion,$_.MinorVersion,$_.BuildNumber}}
                    $ret.cmdOut.serviceType = "wmi"
                }                
                catch {
                    $ret.status = 1
                    $ret.errOut = [PSCustomObject]@{message=$_.Exception.Message}
                }
                $ret
            } #End of Scriptblock
            #Execute scriptblock over loopback connection with cached creds
            $params = @{
                ScriptBlock=$sb;
                ComputerName=[Environment]::MachineName;
                ArgumentList=$Computer;
                Credential=$cachedCreds;
                ErrorAction="Stop"                        
            }
            try {
                $rtn = Invoke-Command @params
            }
            catch {
                $rtn.status=1
                $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
            }                     
        } else {
            # Cannot access cached Credentials
            return $cred                    
        }
    } else {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message="You must supply the servicePath as -Computer parameter"}                
    }
    $rtn       
}

Function Test-MorpheusServicePath {
    [CmdletBinding()]
    param(
        $Computer=$null
    )
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    if ($Computer) {
        #Try WinRm first
        $rtn = Test-WinRmServicePath -Computer $Computer
        if ($rtn.status -gt 0) {
            #Then wmi
            $rtn = Test-WmiServicePath -Computer $Computer
        }
        $soaServers = Get-AuthoritativeServers -Name $Computer
    } else {
        $rtn = Test-LocalServicePath
        $soaServers = Get-AuthoritativeServers
    }
    # Discovered DNS servers from SOA record
    $rtn.cmdOut.domainSOAServers = $soaServers.cmdOut
    # $rtn.cmdOut.serviceType should now be set to winrm, wmi or local 
    $rtn | ConvertTo-Json -Depth 5 -Compress
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
               $ret.cmdOut = $existingRecord | Format-List | Out-String -Width 512
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
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
        $start = Get-Date
        $params=@{ErrorAction="Stop"}
        if ($serviceHost) {
            $params.Add("ComputerName",$serviceHost)
        }
        try {
            #Collect
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
        $ret.collectionTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
        $ret
    } # End GetZoneBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
    $start = Get-Date
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
        $rtn.status = 1
        $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
    }
    $rtn.elapsedTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
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
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
        $start = Get-Date
        $params=@{
            ZoneName=$zone;
            ErrorAction="Stop"
        }
        if ($serviceHost) {
            $params.Add("ComputerName",$serviceHost)
        }
        try {
            #Collect
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
        $ret.collectionTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
        $ret
    } #end GetZoneRecordBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
    $start = Get-Date
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
    $rtn.elapsedTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
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
        $ret=[PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
        $start = Get-Date
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
        if ($ServiceHost) {
            $getparams.Add("ComputerName",$ServiceHost)
        }
        if ($Name) {
            $getparams.Add("Name",$Name)
        }

        try {
            if ($data) {
                $ret.cmdOut=Get-DnsServerResourceRecord @getparams | Where-Object {$_.RecordData.$dataPropertyName -eq $data}
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
        $ret.collectionTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
        $ret
    } # End of ScriptBlock

    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null;collectionTime=0;elapsedTime=0}
    $start = Get-Date
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
    $rtn.elapsedTime = (New-TimeSpan -Start $start).TotalMilliseconds.ToString("#")
    $rtn | ConvertTo-Json -Depth 5 -Compress
}
