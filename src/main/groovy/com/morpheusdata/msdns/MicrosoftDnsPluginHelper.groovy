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

import groovy.util.logging.Slf4j
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Slf4j
class MicrosoftDnsPluginHelper {

    // Powershell Helper module resource name - should be in resources folder available in the classPath
    private static String getHelperResourceName() {
        return "morpheusdnshelper.ps1"
    }

    // Returns the Powershell Helper module file name for use on Windows RPC host
    // The Path is always %LOCALAPPDATA% on the Windows Host
    public static String getHelperFile() {
        return "morpheusDnsPluginHelper_v22.ps1"
    }

    // Load a Project resource from resourcePath and return a String
    private static String loadResourceString(String resourcePath) {
        
        try {
            log.debug("loadResourceString - loading content from ${resourcePath}")
            InputStream inputStream = MicrosoftDnsPluginHelper.class.getClassLoader().getResourceAsStream(resourcePath)
            if (inputStream) {
                InputStreamReader isReader = new InputStreamReader(inputStream,StandardCharsets.UTF_8)
                BufferedReader reader = new BufferedReader(isReader)
                StringBuffer sb = new StringBuffer()
                String line
                while((line = reader.readLine())!= null) {
                    sb.append(line)
                    sb.append(System.getProperty("line.separator"))
                }
                reader.close()
                isReader.close()
                inputStream.close()
                return sb.toString()
            }
        }
        catch(e) {
            log.error("loadResourceString: Failed to load required resource ${resourcePath} exception ${e.getMessage()}")
            return null
        }
    }

    public static String morpheusDnsHelperScript() {
        
        log.debug("morpheusDnsHelperScript - Loading Powershell Module via classLoader. Resource name: ${MicrosoftDnsPluginHelper.getHelperResourceName()}")
        return MicrosoftDnsPluginHelper.loadResourceString(MicrosoftDnsPluginHelper.getHelperResourceName())
    }

   
    /*
    * Powershell commands to transfer the Morpheus DNS Helper module in 1K base64 chunks to the serviceUrl (Windows Computer) so that subsequent calls can load the module
    * from a file on the Windows Server. The Helper module is located in the user profile LOCALAPPDATA. 
    * The Helper Module file name is defined by the static method getHelperFile() in this class
    */
    public static String copyHelperBlockScript(String b64Block) {
        def block = b64Block ?: ""
        def fileName = getHelperFile()
        def copyCmd = '''
            $b64Chunk = "<%block%>"
            $rtn = [PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
            $scriptFile = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "<%helperfile%>"
            try {
                [System.IO.File]::AppendAllText($scriptFile,[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64Chunk)),[System.Text.Encoding]::UTF8)
            }
            catch {
                rtn.status = 1
                rtn.errOut = [PSCustomObject]@{message="Error transferring script file {0} - Exception {1}" -F $scriptFile,$_.Exception.message}
            }
            $rtn | ConvertTo-Json -depth 2 -Compress
        '''
        log.debug("copyHelperBlockScript - Transfering Powershell Helper ${fileName} - block ${block}")
        return copyCmd.stripIndent().replace("<%helperfile%>",fileName).replace("<%block%>",block)
    }

    /*
    * Test the integrity of the cached Morpheus DNS Helper Module. If the local md5 checksum does not match the one expected by the Plugin
    * content then the local copy is removed
    */
    public static String testHelperFileScript() {
        def fileName = getHelperFile()
        // md5 hash of the Morpheus DNS Helper module content
        def md5Hash = morpheusDnsHelperScript().md5()
        log.info("testHelperFileScript - Checking for valid Helper script fileName: ${fileName} - MD5: ${md5Hash}")
        def testScript = '''
            $rtn=[PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
            $s = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "<%helperfile%>"
            $chksum = "<%chksum%>".ToUpper()
            if (Test-Path -Path $s) {
                try {
                    $fc = Get-Content -Raw -Path $s
                    $strAsStream = [System.IO.MemoryStream]::new()
                    $writer = [System.IO.StreamWriter]::new($strAsStream)
                    $writer.Write($fc)
                    $writer.Flush()     
                    $strAsStream.Position = 0
                    $h = (Get-FileHash -InputStream $strAsStream -Algorithm MD5).Hash.ToUpper()
                    $strAsStream.Close()
                    $writer.Close()
                    if ($h -eq $chksum) {
                        $rtn.status = 0
                        $i=New-Module -Name "MorpheusDnsHelper" -ScriptBlock ([ScriptBlock]::Create($fc))
                        $rtn.cmdOut = [PSCustomObject]@{loadedModule=$i.Name;md5Chksum=$h}
                    } else {
                        $i=Remove-Item -Path $s -Force
                        $rtn.status = 9
                        $rtn.errOut = [PSCustomObject]@{message="Powershell Helper script failed chksum {0}. Removing Script {1}" -F $h,$s}
                    }
                }
                catch {
                    $rtn.status = 1
                    $rtn.errOut = [PSCustomObject]@{message=$_.Exception.Message}
                } 
            } else {
                $rtn.status = 9
                $rtn.errOut = [PSCustomObject]@{message="Cannot Find Powershell Helper script {0}" -F $s}
            }
            $rtn | ConvertTo-Json -Depth 3 -Compress
        '''

        return testScript.stripIndent()
            .replace("<%helperfile%>",fileName)
            .replace("<%chksum%>",md5Hash)
    }

    /*
    * Returns the template Powershell script that loads the local Helper script as a Dynamic Module
    * The replacement string <%usercode%> is replaced by the actual Powershell Function call to perform the task required
    */
    public static String templateHelperScript() {
        def fileName = getHelperFile()
        def installScript = '''
            $rtn=[PSCustomObject]@{status=0;errOut=$Null;cmdOut=$Null}
            $s = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "<%helperfile%>"
            if (Test-Path -Path $s) {
                $i=New-Module -Name "MorpheusDnsHelper" -ScriptBlock ([ScriptBlock]::Create($(Get-Content -Raw -Path $s)))
            } else {
                $rtn.status = 1
                $rtn.errOut = [PSCustomObject]@{message="Cannot Find Powershell Helper script {0}" -F $s}
                return $rtn | ConvertTo-Json -depth 2 -Compress
            }
            # Call the module functions returning the output to variable $rtn
            <%usercode%>
            # Return results which will be json string
            $rtn
        '''
        log.debug("templateHelperScript - Returning Powershell Snippet to load Helper Script ${fileName}")
        return installScript.stripIndent().replace("<%helperfile%>",fileName)
    }
}
