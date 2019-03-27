param
(
[string]$Role
)


$DataPath="H:\MSSQL\DATA"
$LogPath="O:\MSSQL\DATA"
$BackupPath="E:\MSSQL\bak"
$TempDBPath="T:\MSSQL\DATA"
$SQLServerAcct=""
$SQLAgentAcct=""
$SQLAdminAcct=""
$scriptFolderUrl="https://raw.githubusercontent.com/Microsoft/MSITARM/develop/all-scripts/"
$logfilename="C:\WindowsAzure\Logs\TWSCustomInstallLog.txt"

$XpertEnvironmentname="xpertdata.data.microsoft.com"
$XpertTWSEnvName="" #If Xpert Install these variable need to be paramterised.
$XpertROle="" #If Xpert Install these variable need to be paramterised.
$xpertservicekey="" #If Xpert Install these variable need to be paramterised.

function SecureStringTotext($encrypted) 
{
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encrypted)       
return $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
}

 $InstanceName =Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances | Select-Object -ExpandProperty InstalledInstances | ?{$_ -eq 'MSSQLSERVER'}
    $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName | Select-Object -ExpandProperty $InstanceName;
    $DataPath   = $DataPath.replace('MSSqlServer',$InstanceFullName)
    $LogPath    = $LogPath.replace('MSSqlServer',$InstanceFullName)
    $BackupPath = $BackupPath.replace('MSSqlServer',$InstanceFullName)
    $TempDBPath = $TempDBPath.replace('MSSqlServer',$InstanceFullName)
    $ErrorPath = $(split-path $("$dataPath") -Parent)+"\Log"
        
   # $SQLServerAccount = $($SQLServerAcct.UserName)
   # $SQLServerPassword =  SecureStringTotext(($SQLServerAcct.Password))

   # $SQLAgentAccount = $($SQLAgentAcct.UserName)
   # $SQLAgentPassword =  SecureStringTotext(($SQLAgentAcct.Password))

   # $SQLAdminAccount = $($SQLAdminAcct.UserName)
   # $SQLAdminPassword =  SecureStringTotext(($SQLAdminAcct.Password))

    #END OF GLOBAL VARIABLES

function InstallXpertAgent
{
$scriptPath = "C:\Packages\Plugins\SupportFiles\InstallNonAPXpertAgent"
$DestinationPath="E:\XpertAgent"
$zipPAth=$ScriptPath + "\NonAPXpertBinaries.zip"
Stop-Process -Name Xpert.Agent* -Force -ErrorAction Continue
Expand-Archive $zippath -DestinationPath $DestinationPath -Force
$appDir = “$DestinationPath\app”
$dataDir = “$DestinationPath\data”
[Environment]::SetEnvironmentVariable(“APPDIR”, $appDir,[EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable(“DATADIR”, $dataDir,[EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable(“XPERT_AGENT_INSTALL_LOCATION”, “$appDir\XpertAgent”,[EnvironmentVariableTarget]::Machine)
icacls $appDir /grant "NETWORK SERVICE:(OI)(CI)F"
icacls $dataDir /grant "NETWORK SERVICE:(OI)(CI)F"

#Setup DataCollectorConfig.xml
    Write-Host "Setting up DataCollector.config.xml..."

    $targetEndpoint = ($Script:XpertEnvironmentname)
    $xpertDataCollectorConfig = Get-Content $appDir\xpertagent\DataCollector.config.xml
    $xpertDataCollectorConfig | % { $_.Replace("XPERTENDPOINT", $targetEndpoint) } | Set-Content $appDir\xpertagent\DataCollector.config.xml

    #Setup AgentIdentityConfiguration.xml
    Write-Host "Setting up AgentIdentityConfiguration.xml..."

    $agentIdentityConfiguration = Get-Content $datadir\AgentIdentityConfiguration.xml
    $agentIdentityConfiguration | % { $_.Replace("ENVIRONMENT", $Script:XpertTWSEnvName) } | % { $_.Replace("ROLE", $Script:XpertROle) } | % { $_.Replace("SERVICEKEY", $SCript:xpertservicekey) } | Set-Content $datadir\AgentIdentityConfiguration.xml

    #Setup XpertAgent.xml file
    Write-Host "Setting up XpertAgent task script..."

    $xpertAgentTaskScript = Get-Content $appDir\xpertagent\XpertAgent.xml
    $xpertAgentTaskScript | % { $_.Replace("XPERT_AGENT_INSTALL_LOCATION", “$appDir\XpertAgent”) } | Set-Content $appDir\xpertagent\XpertAgent.xml

    #Setup XpertAgentStarter.xml file
    Write-Host "Setting up XpertAgentStarter task script..."

    $xpertAgentStarterTaskScript = Get-Content $appDir\xpertagent\XpertAgentStarter.xml
    $xpertAgentStarterTaskScript | % { $_.Replace("XPERT_AGENT_INSTALL_LOCATION", “$appDir\XpertAgent”) } | Set-Content $appDir\xpertagent\XpertAgentStarter.xml

    #Setup Task Scheduler Tasks
    Write-Host "Setting up Task Scheduler tasks..."

    Schtasks /Create /XML $appDir\xpertagent\XpertAgent.xml /TN XpertAgent /f
    Schtasks /Create /XML $appDir\xpertagent\XpertAgentStarter.xml /TN XpertAgentStarter /RU System /f

    #Start the XpertAgentStarter Scheduled Task
    Schtasks /Run /TN XpertAgentStarter
    
    #Give the Scheduled Task time to start the Agent
    Sleep 60

    $processActive = Get-Process Xpert.Agent -ErrorAction SilentlyContinue
If($processActive -eq $null)
{
    Write-Host -backgroundcolor DarkRed $env:COMPUTERNAME,"XpertAgent not started"
}
Else
{
    Write-Host -backgroundcolor DarkGreen $env:COMPUTERNAME,"XpertAgent started"
}

}

function DiskConfiguration()
{
try{
Write-FileLog -message "-----Begin-DiskConfiguration------"

Write-FileLog -message "Stopping Shell Detection Service"
$role=($Script:Role)
Stop-Service -Name ShellHWDetection

Write-FileLog -message "Extending C:\ to maximum Size"
#Extending C to maximum available size
$size = (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber 2)
$Csize=(Get-Partition -DiskNumber 0 -PartitionNumber 2)
if ($Csize.Size -lt $size.SizeMax)
{
Resize-Partition -DiskNumber 0 -PartitionNumber 2 -Size $size.SizeMax
}

Write-FileLog -message "Initializing All RAW Disks"
#INitializing the data disk and assigning drive letters.
$disks=Get-Disk | Where partitionstyle -eq 'RAW'
foreach ($disk in $disks)
{
Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru 
Switch ($disk.Number)
{
2
{
if ($role -ne "SQL")
{
New-Partition -DiskNumber 2 -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'D-Data' -Confirm:$false 
}
else
{
New-Partition -DiskNumber 2 -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Binaries' -Confirm:$false 
}
Write-FileLog -message "D:\ Created"
}
3
{
if ($role -ne "SQL")
{
New-Partition -DiskNumber 3 -DriveLetter E -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'E-Data' -Confirm:$false 
}
else
{
New-Partition -DiskNumber 3 -DriveLetter E -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Bak' -Confirm:$false 
}
Write-FileLog -message "E:\ Created"
}
4
{
New-Partition -DiskNumber 4 -DriveLetter H -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Data' -Confirm:$false 
Write-FileLog -message "H:\ Created"
}
5
{
New-Partition -DiskNumber 5 -DriveLetter O -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Log' -Confirm:$false
Write-FileLog -message "O:\ Created"
}
6
{
New-Partition -DiskNumber 6 -DriveLetter T -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Tempdb' -Confirm:$false 
Write-FileLog -message "T:\ Created"
}
}
sleep 5
}
Write-FileLog -message "Starting Shell Detection Service"
Start-Service -Name ShellHWDetection
Write-FileLog -message "-----End-DiskConfiguration------"
Write-FileLog -message ""
}
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function enableIIS()
{
try
{
Write-FileLog -message "-----Begin-enableIIS------"
Set-ExecutionPolicy Bypass -Scope Process
Write-FileLog -message "Enabling IIS Features"

Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment

Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45

Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Security
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Performance
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools
Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASP
Write-FileLog -message "Completed Enabling IIS Features"
Write-FileLog -message "-----End-enableIIS------"
Write-FileLog -message ""
}
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function RemoveDefaultWebsite()
{
try
{
Write-FileLog -message "-----Begin-RemoveDefaultWebsite------"
Write-FileLog -message "Removing Default Website"
Import-Module WebAdministration
Remove-WebSite -Name 'Default Web Site'   
Write-FileLog -message "-----End-RemoveDefaultWebsite------"
Write-FileLog -message 
}
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function ConfigureEventLog()
{
try 
{
Write-FileLog -message "-----Begin-ConfigureEventLog------"
Write-FileLog -message "Creating EveningLog"
new-EventLog -LogName Application -source 'AzureArmTemplates' -ErrorAction SilentlyContinue
Write-FileLog -message "-----End-ConfigureEventLog------"
Write-FileLog -message 
} 
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function AddFirstSQLAdmin()
{
try
{
$SQLFile="c:\Packages\Plugins\SupportFiles\SQLCommands.sql"
Write-FileLog -message "-----Begin-AddFirstSQLAdmin------"
Write-FileLog -message "Stopping SQL Server"
Stop-Service -Name "MSSQLSERVER" -Force
$sqlservice = Get-Service "mssqlserver" 
Write-FileLog -message "Starting SQL Server in Single Admin Mode"
$sqlservice.Start("-m")
Write-FileLog -message "Invoking $SQLFile"
#Invoke-Sqlcmd -Query "CREATE LOGIN [phx\JIT-MDOLLAR-ADMIN-PROD] FROM WINDOWS;EXEC sp_addsrvrolemember 'phx\JIT-MDOLLAR-ADMIN-PROD','sysadmin';"  -ErrorAction Continue
Invoke-Sqlcmd -InputFile $SQLFile
Write-FileLog -message "Finished Executing $SQLFile"
Write-FileLog -message "Stopping SQL Service"
Stop-Service -Name "MSSQLSERVER" -Force
Write-FileLog -message "Starting SQL Service with normal mode"
Start-Service -Name "MSSQLSERVER"
Write-FileLog -message "-----End-AddFirstSQLAdmin------"
Write-FileLog -message ""
}
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function DriveCheck($DriveLetter)
{
     try {
                    Write-FileLog -message "-----Begin-DriveCheck------"
                   $filter="DriveLetter = '" + $DriveLetter + "'"
                    $diskarray=gwmi win32_volume -Filter $filter


                    if($diskArray -eq $nothing) {

                        Write-FileLog -message "$DriveLetter - NOT FOUND"
                        throw "Drives not available as expected"

                        }else{Write-FileLog -message "$DriveLetter - Drives Ready"}
                        Write-FileLog -message "-----End-DriveCheck------"
                        Write-FileLog -message ""
                    } 
                    
                    Catch [Exception]
                     {
                        Write-FileLog -message "Exception Occured..."
                        Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
                     }  
}

function CreateFolder($root)
{
try
{
Write-FileLog -message "-----Begin-CreateFolder-------"
if($(test-path -path $root) -ne $true)
                         {
                         New-Item -ItemType Directory -Path $Root
                         }
Write-FileLog -message "-----End-CreateFolder-------"
}
Catch [Exception]
   {
   Write-FileLog -message "Exception Occured..."
   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
   }  
}

function ConfigureStartupPath()
{
try { 
                        Write-FileLog -message "-----Begin-ConfigureStartupPath-------"
                        $Root = "C:\SQLStartup"

                         CreateFolder($Root)

                        if($(test-path -path $root) -eq $true) {
                            
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
                                
                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule
                                                                                           
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            #Setting the Change
                            Set-Acl $Root $acl
                            Write-FileLog -message "-----End-ConfigureStartupPath-------"
                            
                      }                         
                       
                    } 
                    
                    Catch [Exception]
                     {
                                Write-FileLog -message "Exception Occured..."
                                Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
                     }  
                    
}

function ConfigureDataPath()
{
 try { 
 Write-FileLog -message "-----Begin-ConfigureDataPath-------"

 
                        $Root = ($Script:DataPath)
                         CreateFolder($Root)
                          if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("Phx\_wapsbe", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            
                            #Setting the Change
                            Set-Acl $Root $acl
                            Write-FileLog -message "-----End-ConfigureDataPath-------"
                      }                         
                       
                    } 
                    Catch [Exception]
                    {
                        Write-FileLog -message "Exception Occured..."
                        Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
                    }  
                    
}

function ConfigureLogPath()
{
try { 
 Write-FileLog -message "-----Begin-ConfigureLogPath-------"
                        $Root = ($Script:logPath)
                         CreateFolder($Root)
                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")   
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("Phx\_wapsbe", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                            Write-FileLog -message "-----End-ConfigureLogPath-------"
                      }                         
                       
                    } 
                    Catch [Exception]
                       {
                       Write-FileLog -message "Exception Occured..."
                       Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
                       }  
                    
}


function ConfigureTempdbPath()
{
try { 
 Write-FileLog -message "-----Begin-ConfigureTempdbPath-------"
                        $Root = ($Script:TempdbPath)
                        CreateFolder($ROot)
                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                            Write-FileLog -message "-----End-ConfigureTempdbPath-------"
                      }                         
                       
                    } 
                    Catch [Exception]
                   {
                   Write-FileLog -message "Exception Occured..."
                   Write-FileLog -message "Exception $_.Exception.GetType().FullName : $_.Exception.Message"
                   }  
}

function ConfigurebackupPath()
{
try { 
 
                        $Root = ($Script:BackupPath)
                        CreateFolder($Root)
                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule


                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
    
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("Phx\_wapsbe", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("Phx\tws-webstore", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                  
                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigurebacakupPath: $errorMessage"
                       }
                    }
}

function ConfigureErrorPath()
{
        try { 
 
                        $Root = ($Script:ErrorPath)
                        CreateFolder($Root)
                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureErrorPath: $errorMessage"
                       }
                    }
}

function ConfigureServerLoginMode()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    try {  

                        ############################################                     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $srv.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Integrated
                        $srv.Alter()
                       
                    } catch {
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureServerLoginMode: $errorMessage"
                        }
                    }
                }
}

function ConfigureMaxDop()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    try {

                        ############################################         
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                             
                        ############################################
                        # Set Max D.O.P.:  n=num of procs
                        ############################################
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $coreCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                  
                        if($($coreCount) -eq 1) { $maxDop=1 }
                        if($($coreCount) -ge 2 -and $($coreCount) -le 7) { $maxDop=2 }
                        if($($coreCount) -ge 8 -and $($coreCount) -le 16) { $maxDop=4 }
                        if($($coreCount) -gt 16) { $maxDop=8 }
                                          
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$maxDop
                        $srv.configuration.Alter();
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxDop: $errorMessage"
                        } 
                    }
                }
}

function ConfigureDefaultLocations()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
    
                if($sqlInstances -ne $null){
                   
                    try {
                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $BackupDir = ($Script:backupPath)
                       
                        $srv.BackupDirectory = $BackupDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup compression to true
                        ###########################################
                        $srv.Configuration.DefaultBackupCompression.ConfigValue = $true
                        $srv.Configuration.Alter()

                        ###########################################
                        #  Set the data location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultFileDir = ($Script:DataPath)
                        
                        $srv.defaultfile = $DefaultFileDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultLog = ($Script:LogPath)
                        
                        $srv.DefaultLog = $DefaultLog
                        $srv.Alter()                 
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDefaultLocations: $errorMessage"
                        }
                    }
                }
}

function ConfigureMaxMemory()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ############################################
                        # Set Max Server MemorySQL
                        ############################################

                        $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName:$env:COMPUTERNAME |Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
                      
                       if($PhysicalRAM -eq 7) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096 
                        }
                        if($PhysicalRAM -eq 8) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096
                        }
                         if($PhysicalRAM -eq 14) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 10240 
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 19456   
                        }
                         if($PhysicalRAM -eq 28) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 22528 
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 56) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 45056
                        }

                        if($PhysicalRAM -eq 64) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 52224
                        }
                        if($PhysicalRAM -eq 72) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 96) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 77824
                        }
                         if($PhysicalRAM -eq 112) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 91136 
                        }
                        if($PhysicalRAM -eq 128) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 104448
                        }
                         if($PhysicalRAM -eq 140) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 114688 
                        }
                         if($PhysicalRAM -eq 224) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 196608 
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 229376
                        }
                         if($PhysicalRAM -eq 448) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 425984 
                        }
                        if($PhysicalRAM -eq 512) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 491520
                        }
                        if($PhysicalRAM -eq 768) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 753664
                        }
                        if($PhysicalRAM -eq 1024) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 1015808
                        }
                        $srv.configuration.Alter(); 
                                                
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxMemory: $errorMessage"
                       }
                    }
                }
}

function ConfigureSQLAgent()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){
                   
                    try {   
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn 
                                              
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                            if($sqlInstances.State -eq 'Stopped'){
                                net start SQLSERVERAGENT
                            }

                            $db = New-Object Microsoft.SqlServer.Management.Smo.Database
                            $db = $srv.Databases.Item("msdb")
                            # Select SQLAgent 
                            $SQLAgent = $db.parent.JobServer ;
                     
                            # Show settings
                            $CurrentSettings = $SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            #$CurrentSettings | ft -AutoSize ;
                            $TargetMaximumHistoryRows = 100000;
                            $TargetMaximumJobHistoryRows = 1000 ;

                            $SQLAgent.MaximumHistoryRows = $TargetMaximumHistoryRows ;
                            $SQLAgent.MaximumJobHistoryRows = $TargetMaximumJobHistoryRows ; 
                            $db.Parent.JobServer.SqlServerRestart=1
                            $db.Parent.JobServer.SqlAgentRestart=1
                            $SQLAgent.Alter();
                     
                            # ensuring we have the latest information
                            $SQLAgent.Refresh();
                            #$SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            $db.Parent.ConnectionContext.Disconnect();

                            CD HKLM:\
                            $Registry_Key ="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT\"
                            Set-ItemProperty -Path $Registry_Key -Name Start  -Value 2 
                            CD C:\

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureSQLAgent: $errorMessage"
                        }
                    }
                }
}

function MoveMasterFiles()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 

                        ################################################################
	                    # Data.
                        ################################################################                     
                        $DataPath = ($Script:dataPath)
                        $logPath = ($Script:logPath)
                        $ErrorPath = ($Script:ErrorPath)
                	    $flagsToAdd = "-T1118"

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                        ################################################################
	                    # Alter DB...
                        ################################################################
        
                           $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                        if($sqlInstances -ne $null -and $sqlInstances.State -eq 'Running'){
	                        $q = "ALTER DATABASE [master] MODIFY FILE (NAME = master, FILENAME = '$($DataPath)\master.mdf')"
		                    Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [master] MODIFY FILE (NAME = mastlog, FILENAME = '$($logPath)\mastlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                        }

                        ################################################################

                        ################################################################
                        #Change the startup parameters 
                        ################################################################
                        $hklmRootNode = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
                            $props = Get-ItemProperty "$hklmRootNode\Instance Names\SQL" 
                            $instances = $props.psobject.properties | ?{$_.Value -like 'MSSQL*'} | select Value 

                            $instances | %{ $inst = $_.Value;}

                            $regKey = "$hklmRootNode\$inst\MSSQLServer\Parameters" 
                            $props = Get-ItemProperty $regKey 
                            $params = $props.psobject.properties | ?{$_.Name -like 'SQLArg*'} | select Name, Value 
                            $flagset=$false

                            $c=0
                            foreach ($param in $params) { 
                                if($param.Value -match '-d') {
                                    $param.value = "-d$datapath\master.mdf"
                                } elseif($param.Value -match '-l') {
                                    $param.value = "-l$logpath\mastlog.ldf"
                                } elseif($param.Value -match '-e') {
                                     $param.value = "-e$errorpath\ERRORLOG"
                                } elseif($param.Value -match '-T') {
                                     $flagset=$true
                                } 
                                Set-ItemProperty -Path $regKey -Name $param.Name -Value $param.value 

                                $c+=1
                             }
                             if(!$flagset) {
                                $newRegProp = "SQLArg"+($c) 
                                Set-ItemProperty -Path $regKey -Name $newRegProp -Value $flagsToAdd 
                             }
                               
                             $q = "EXEC msdb.dbo.sp_set_sqlagent_properties @errorlog_file=N'" +$ErrorPath + "\SQLAGENT.OUT'"
                             Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                             
                            ################################################################

                            ################################################################
                            # Stop SQL, move the files, start SQL 
                            ################################################################
                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                            
                             $readylog = $(test-path -Path $("$($logPath)\mastlog.ldf"))
                             $readyData = $(test-path -Path $("$($DataPath)\master.mdf"))

                                  #Move
                              if(!$readyData) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'master.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force }
                              }
                              if(!$readyLog) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'mastlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force }
                              }
                               
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                       }                                                     
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMasterFiles: $errorMessage"
                        } else {$errorMessage}
                    }
                }

}

function MoveModelFiles()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = ($Script:dataPath)
                        $logPath = ($Script:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modeldev, FILENAME = '$($DataPath)\model.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modellog, FILENAME = '$($logPath)\modellog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                               
                                $readylog = $(test-path -Path $("$($logPath)\modellog.ldf"))
                                $readyData = $(test-path -Path $("$($DataPath)\model.mdf"))

                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'model.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'modellog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveModelFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
}

function MoveMSDBFiles()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = ($Script:dataPath)
                        $logPath = ($Script:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBData, FILENAME = '$($DataPath)\MSDBData.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBlog, FILENAME = '$($logPath)\MSDBlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue


                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                                
                               $readylog = $(test-path -Path $("$($logPath)\MSDBlog.ldf"))
                               $readyData = $(test-path -Path $("$($DataPath)\MSDBData.mdf"))
                                                               
                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBData.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                 }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                                           
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMSDBFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
}

function ConfigureModelDataFile()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $MyDatabase.RecoveryModel = "Simple"                                            
                        $MyDatabase.Alter()

                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size -or (5*1024) -ne $dbf.Growth) {
                               $DBF.MaxSize = -1
                               $dbf.Growth = (5*1024)
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB, Filegrowth to 5MB"}
                                                      

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelDataFile: $errorMessage"
                        }
                    }
                }
}

function ConfigureModelLogFile()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                            

                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()

                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelLogFile: $errorMessage"
                        }
                    }
                }
}

function ConfigureMSDBDataFile()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.MaxSize = -1
                                 $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (50*1024)
                                $dbf.Growth = (5*1024)
                                $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB,Filegrowth to 5MB, unlimited growth"}
                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBDataFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function ConfigureMSDBLogFile()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
       
                        foreach ($DBF in $MyDatabase.LogFiles) {
                                                       
                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()
                                                         
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function ConfigureAuditing()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try{
                        INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regwrite] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 30"
                    }catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureAuditing: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function ConfigureBuiltInAdmins()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try {                            
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureBuiltInAdmins: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function MoveTempdbFiles()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=($Script:TempDbPath).split("\")[0] 
                        $TempPath = ($Script:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, FILENAME = '$($TempPath)\tempdb.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, FILENAME = '$($TempPath)\templog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            "$(Get-Date -Format g) Restarting SQL Server."
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Running'){
                                    net stop sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Running'){
                                    net stop mssqlserver
                                    }
                                    start-sleep 30
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Stopped'){
                                    net start sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Stopped'){
                                    net start mssqlserver
                                    }
                                Start-Sleep 30
                                               
                            } catch{
                                [string]$errorMessage = $Error[0].Exception
                                if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveTempdbFiles: $errorMessage"
                                } else {$errorMessage}
                            }
                    }
}

function AddTempdbFiles()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=($Script:TempDbPath).split("\")[0] 
                        $TempPath = ($Script:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
            
                        #maximum of 8 to start, the additional ones to be added by the server Owners
                        if($fileCount -gt 8){ $fileCount = 8 }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################                       
	                        "$(Get-Date -Format g) Creating remaining data files..."

                            for ($i = 2; $i -le $fileCount; $i++) {

                                $msg="Create tempdev$($i)"
                                           
                                try{
                                    
                                        $q = "IF NOT EXISTS(SELECT 1 FROM tempdb.dbo.sysfiles WHERE name = 'tempdev$($i)') Begin ALTER DATABASE [tempdb] ADD FILE ( NAME = tempdev$($i), SIZE = $($fileSize)MB, MAXSIZE = 'unlimited', FILEGROWTH = $($fileGrowthMB)MB, FILENAME = '$($TempPath)\tempdb$($i).mdf') END "; 
		                                Invoke-Sqlcmd -Database master -Query $q -QueryTimeout 10000 -ErrorAction SilentlyContinue
                                    
                                    }catch{
                                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                                        }else {$errorMessage}
                                    }
                                                                                               
                            Restart-Service -displayname "SQL Server (MSSQLSERVER)" -Force

		                        	                        
                        }

                          

                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "AddTempdbFiles: $errorMessage"
                        } else {$errorMessage}
                   }
                }
}

function ConfigureTempDataFile()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path ($Script:tempdbpath) -Qualifier)  
                        $TempPath = ($Script:TempDbPath)

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount =($cpu.NumberOfCores | Measure-Object -Sum).Sum

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
                                                                           
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = $($fileSize)
                               $dbf.Growth = "$fileGrowthMB"
                               $dbf.Alter()                        
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempDataFile: $errorMessage"
                        }else {$errorMessage}
                    }
                }
}

function ConfigureTempLogFile()
{ 
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path ($Script:tempdbpath) -Qualifier)  
                        $TempPath = ($Script:TempDbPath)
                    
                        
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $DatafileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $DatafileSize = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $DatafileSize = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        if($fileCount -gt 8){ $fileCount = 8 }
                        $LogfileSize     = $(.25 * $($fileCount * $DatafileSize))

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                        $MyDatabase = $srv.Databases[$DatabaseName]
          
                        foreach ($DBF in $MyDatabase.LogFiles) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = ($LogfileSize)
                               $dbf.Growth = $fileGrowthMB
                               $dbf.Alter()

                               "$($DBF.Name) Size is $($dbf.Size) MB,Growth is $($dbf.Growth) MB, MaxSize is $($dbf.MaxSize) MB"

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function ConfigureMasterDataFile()
{
$sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {  
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterDataFile: $errorMessage"
                        }
                    }
                }
}

Function ConfigureMasterLogFile()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                
                if($sqlInstances -ne $null){
                   
                    try {    
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (20*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterLogFile: $errorMessage"
                        }
                    }
                }

}

function ConfigureStartupJob()
{
if($(test-path -path C:\SQLStartup) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile(($Script:scriptFolderUrl) + "SQL-Startup.ps1","C:\SQLStartup\SQL-Startup.ps1")

                    if($(test-path -path C:\SQLStartup\SQL-Startup.ps1) -eq $true) {
                        C:\SQLStartup\SQL-Startup.ps1 ($Script:TempDBPath)
                    }
                }
}

function ConfigureExtendedSprocs()
{
 if($(test-path -path C:\SQLStartup) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile(($Script:scriptFolderUrl) + "PostConfiguration.sql","C:\SQLStartup\PostConfiguration.sql")

                    if($(test-path -path C:\SQLStartup\PostConfiguration.sql) -eq $true) {
                         $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                    if($sqlInstances -ne $null){

                        ############################################
                        try {
               
                             write-verbose "Extended Sprocs on $server"
                                                    
                            Invoke-SQLCmd -ServerInstance $($env:computername) -Database 'master' -ConnectionTimeout 300 -QueryTimeout 600 -inputfile "C:\SQLStartup\PostConfiguration.sql"                       

                        } catch{
                            [string]$errorMessage = $_.Exception.Message
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 5001 -entrytype Error -message "PostConfiguration.SQL: $errorMessage"
                            }else {$error}
                            throw $errorMessage
                        }
                     }
                 }
              }
}

function ConfigureSQLAccount()
{
 $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try {                            
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $NtLogin = ($Script:SQLServerAccount) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $NtLogin
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional

                        $login.AddToRole('sysadmin')
                        $login.Alter()

                       

                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureBuiltInAdmins: $errorMessage"
                        } else {$errorMessage}
                    }
                }
}

function ConfigureSQLServerService()
{
                              
Write-FileLog -message "-----Begin-ConfigureSQLServerService------"

   
                    ############################################             
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                    ############################################

                    try {

                                                
                        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                        Write-FileLog -message "Disabling All SQL Related Services expect SQLSERVER, AGENT & WRITER"   
                        #disabling these until the user decides                     
                        $SQLsvc = get-service| where {$_.DisplayName -match 'SQL' -and ($_.name -ne 'MSSQLSERVER' -and $_.Name -ne 'SQLSERVERAGENT' -and $_.Name -ne 'SQLWriter')}
                        $SQLsvc  | %{Set-Service $_.Name -StartupType disabled -Status Stopped -Confirm:$false}
                   Write-FileLog -message "Setting SQL Service Accont to Local System"     
                        #set sql Service
                      
                        $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
                         $svc.SetServiceAccount("LocalSystem","")
                        
                        $svc = $wmi.services | where {$_.DisplayName -match 'SQL'}

                        $svc | ft  name,displayname,serviceaccount,startmode,serviceState  -AutoSize
                         Write-FileLog -message "-----End-ConfigureSQLServerService------"
                        Write-FileLog -message ""
                        
                    } catch {}
                
}


function ConfigureSQLAgentService()
{
Write-FileLog -message "-----Begin-ConfigureSQLAgentService------"
Write-FileLog -message "Setting SQL Agent Service Accont to Local System"

 ############################################             
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                    ############################################

                
                    try {
                        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                        $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
                        $svc.Start()
                        $svc.SetServiceAccount("LocalSystem","")
                        $svc.Stop()
                        $svc.Start()
                        Write-FileLog -message "-----End-ConfigureSQLAgentService------"
                        Write-FileLog -message ""

                        }
                     catch {}
                
}

function ConfigureLocalPolicy()
{
#################Policy Changes####################################

            $ret1=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeLockMemoryPrivilege"

            $ret2=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeManageVolumePrivilege"

}

function Add-LoginToLocalPrivilege 
{

                        #Specify the default parameterset
                        [CmdletBinding(DefaultParametersetName="JointNames", SupportsShouldProcess=$true, ConfirmImpact='High')]
                        param
                            (
                        [parameter(
                        Mandatory=$true, 
                        Position=0,
                        ValueFromPipeline= $true
                                    )]
                        [string] $DomainAccount,

                        [parameter(Mandatory=$true, Position=2)]
                        [ValidateSet("SeManageVolumePrivilege", "SeLockMemoryPrivilege")]
                        [string] $Privilege,

                        [parameter(Mandatory=$false, Position=3)]
                        [string] $TemporaryFolderPath = $env:USERPROFILE
        
                        )

                            #Determine which parameter set was used
                            switch ($PsCmdlet.ParameterSetName)
                            {
                            "SplitNames"
                                                    { 
                        #If SplitNames was used, combine the names into a single string
                                    Write-Verbose "Domain and Account provided - combining for rest of script."
                                    $DomainAccount = "$Domain`\$Account"
                                }
                            "JointNames"
                                                {
                        Write-Verbose "Domain\Account combination provided."
                                    #Need to do nothing more, the parameter passed is sufficient.
                                }
                            }

                        Write-Verbose "Adding $DomainAccount to $Privilege"

                            Write-Verbose "Verifying that export file does not exist."
                            #Clean Up any files that may be hanging around.
                            Remove-TempFiles
    
                        Write-Verbose "Executing secedit and sending to $TemporaryFolderPath"
                            #Use secedit (built in command in windows) to export current User Rights Assignment
                            $SeceditResults = secedit /export /areas USER_RIGHTS /cfg $TemporaryFolderPath\UserRightsAsTheyExist.inf

                        #Make certain export was successful
                        if($SeceditResults[$SeceditResults.Count-2] -eq "The task has completed successfully.")
                        {

                        Write-Verbose "Secedit export was successful, proceeding to re-import"
                                #Save out the header of the file to be imported
        
                        Write-Verbose "Save out header for $TemporaryFolderPath`\ApplyUserRights.inf"
        
                        "[Unicode]
                        Unicode=yes
                        [Version]
                        signature=`"`$CHICAGO`$`"
                        Revision=1
                        [Privilege Rights]" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                                    
                        #Bring the exported config file in as an array
                        Write-Verbose "Importing the exported secedit file."
                        $SecurityPolicyExport = Get-Content $TemporaryFolderPath\UserRightsAsTheyExist.inf

                        #enumerate over each of these files, looking for the Perform Volume Maintenance Tasks privilege
                       [Boolean]$isFound = $false
       
                        foreach($line in $SecurityPolicyExport) {

                         if($line -like "$Privilege`*")  {

                                Write-Verbose "Line with the $Privilege found in export, appending $DomainAccount to it"
                                #Add the current domain\user to the list
                                $line = $line + ",$DomainAccount"
                                #output line, with all old + new accounts to re-import
                                $line | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false

                                Write-verbose "Added $DomainAccount to $Privilege"                            
                                $isFound = $true
                            }
                        }

                        if($isFound -eq $false) {
                            #If the particular command we are looking for can't be found, create it to be imported.
                            Write-Verbose "No line found for $Privilege - Adding new line for $DomainAccount"
                            "$Privilege`=$DomainAccount" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false
                        }

                            #Import the new .inf into the local security policy.
        
                            Write-Verbose "Importing $TemporaryfolderPath\ApplyUserRighs.inf"
                            $SeceditApplyResults = SECEDIT /configure /db secedit.sdb /cfg $TemporaryFolderPath\ApplyUserRights.inf 

                            #Verify that update was successful (string reading, blegh.)
                            if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully.")
                            {
                                #Success, return true
                                Write-Verbose "Import was successful."
                                Write-Output $true
                            }
                            else
                            {
                                #Import failed for some reason
                                Write-Verbose "Import from $TemporaryFolderPath\ApplyUserRights.inf failed."
                                Write-Output $false
                                throw -Message "The import from$TemporaryFolderPath\ApplyUserRights using secedit failed. Full Text Below:
                                $SeceditApplyResults)"
                            }

                        }
                        else
                            {
                                #Export failed for some reason.
                                Write-Verbose "Export to $TemporaryFolderPath\UserRightsAsTheyExist.inf failed."
                                Write-Output $false
                                throw -Message "The export to $TemporaryFolderPath\UserRightsAsTheyExist.inf from secedit failed. Full Text Below: $SeceditResults)"
        
                        }

                        Write-Verbose "Cleaning up temporary files that were created."
                            #Delete the two temp files we created.
                            Remove-TempFiles
    
}

function Remove-TempFiles
{

                        #Evaluate whether the ApplyUserRights.inf file exists
                        if(Test-Path $TemporaryFolderPath\ApplyUserRights.inf)
                        {
                            #Remove it if it does.
                            Write-Verbose "Removing $TemporaryFolderPath`\ApplyUserRights.inf"
                            Remove-Item $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                        }

                        #Evaluate whether the UserRightsAsTheyExists.inf file exists
                        if(Test-Path $TemporaryFolderPath\UserRightsAsTheyExist.inf)
                        {
                            #Remove it if it does.
                            Write-Verbose "Removing $TemporaryFolderPath\UserRightsAsTheyExist.inf"
                            Remove-Item $TemporaryFolderPath\UserRightsAsTheyExist.inf -Force -WhatIf:$false
                        }
}

function Write-FileLog
{
param
(
[string] $message
)
$logfilename=($Script:logfilename)
Write-Output $message | Out-File -FilePath $logfilename -Append -Force
}

function Add-FirewallRules
{
Write-FileLog -message "-----Begin Add-FirewallRules------"
Write-FileLog -message "Adding Inbound Firewall Rules..."
New-NetFirewallRule -Name "DCInbound-I" -DisplayName "TWS_Allow_DCInbound_Ports" -Direction Inbound -LocalPort 139,445,5985,5986 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "IIS-I" -DisplayName "TWS_Allow_IIS_Ports" -Direction Inbound -LocalPort 80,443 -Protocol TCP -Action Allow  -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "SQL-I" -DisplayName "TWS_Allow_SQL_Ports" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "RDP-I" -DisplayName "TWS_Allow_RDP_Port" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
Write-FileLog -message "Completed Inbound Firewall Rules"
Write-FileLog -message "Adding Outbound Firewall Rules"
New-NetFirewallRule -Name "DCInbound-O" -DisplayName "TWS_Allow_DCInbound_Ports" -Direction Outbound -LocalPort 135,139,464,49152-65535,389,636,53,88,445,5985,5986 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "IIS-O" -DisplayName "TWS_Allow_IIS_Ports" -Direction Outbound -LocalPort 80,443 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "SQL-O" -DisplayName "TWS_Allow_SQL_Ports" -Direction Outbound -LocalPort 1433 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "RDP-O" -DisplayName "TWS_Allow_RDP_Port" -Direction Outbound -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
Write-FileLog -message "Completed Outbound Firewall Rules"


Write-FileLog -message "-----End-FirewallRules------"
Write-FileLog -message ""
}


Function InstallGenevaAgent
{
$AgentPath="C:\Packages\Plugins\SupportFiles\GenevaAgent"
$DestinationPath="D:"

Write-FileLog -message "-----Begin-InstallGenevaAgent------"
Write-FileLog -message "Copying Geniva Agent to D:\"
Copy-Item -Path $AgentPath -Destination $DestinationPath -Recurse -Force
Write-FileLog -message "Installing Certificate"
$password=ConvertTo-SecureString -AsPlainText "password" -Force 
Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath "D:\GenevaAgent\tws-geneva-prod-cert.pfx" -Password $password -Exportable
Write-FileLog -message "Creating Schedule Tasks"
Schtasks /Create /XML D:\GenevaAgent\GenevaMonitoringStartup.xml /TN GenevaMonitoringStartup /f
Write-FileLog -message "Starting Schedule Job"
Schtasks /Run /TN GenevaMonitoringStartup
Write-FileLog -message "-----End-InstallGenevaAgent------"
Write-FileLog -message ""
}

Function EnableMSDTC
{
Write-FileLog -message "-----Begin-EnableMSDTC------"
Write-FileLog -message "Installing MSDTC"
Install-Dtc -StartType "AutoStart"
Write-FileLog -message "Configuring Network Setting of  MSDTC"
Set-DtcNetworkSetting -DtcName "Local" -InboundTransactionsEnabled $True -OutboundTransactionsEnabled $True -Confirm:$false
Write-FileLog -message "Allow MSDTC Program in Firewall"
New-NetFirewallRule -Name "AllowMSDTC_I" -DisplayName "TWS_Allow_MSDTC_PROGRAM" -Direction Inbound -Program "%SystemRoot%\system32\msdtc.exe" -Authentication Required -Action Allow
New-NetFirewallRule -Name "AllowMSDTC_O" -DisplayName "TWS_Allow_MSDTC_PROGRAM" -Direction Outbound -Program "%SystemRoot%\system32\msdtc.exe" -Authentication Required -Action Allow
Write-FileLog -message "-----End-EnableMSDTC------"
Write-FileLog -message ""
}

Function Set-TimezonetoPST
{
Write-FileLog -message "-----Begin-Set-Timezone------"
Write-FileLog -message "Updating Server Timezone to PST"
Set-TimeZone -Name "Pacific Standard Time"
Write-FileLog -message "-----End-Set-Timezone------"
Write-FileLog -message ""
}

Function SetFolderPermission
{
param 
(
[string] $folderpath,
[string] $account,
[string] $accesscontrol
)


try{
 if($(test-path -path $folderpath) -eq $true) {
                            $ACL = Get-Acl $folderpath
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ObjectInherit"
                            Write-Host $inherit
                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($account, $accesscontrol, $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                             #Setting the Change
                            Set-Acl $folderpath $acl

                            }
                            }
                            catch
                            {
                            }
}

function twswebstore()
{
New-Item -ItemType Directory -Path E:\MSSQL\Backup -Force
SetFolderPermission "E:\MSSQL\Backup" "Phx\_wapsbe" "FullControl" 
SetFolderPermission "E:\MSSQL\Backup" "Phx\tws-webstore" "FullControl"
SetFolderPermission "E:\MSSQL\Backup" "BUILTIN\Administrators" "FullControl"


New-Item -ItemType Directory -Path E:\webstore\backup -Force
SetFolderPermission "E:\webstore\backup" "BUILTIN\Administrators" "FullControl"
SetFolderPermission "E:\webstore\backup" "Phx\_wapsbe" "FullControl"
SetFolderPermission "E:\webstore\backup" "Phx\tws-webstore" "Read"
SetFolderPermission "E:\webstore\backup" "Phx\tws-webstore" "Write"


New-Item -ItemType Directory -Path H:\Webstore\DATA -Force
New-Item -ItemType Directory -Path O:\Webstore\Log -Force

New-SmbShare -Name "Webstore_backup" -Path "E:\MSSQL\Backup" -FullAccess "phx\tws-webstore","phx\_wapsbe","builtin\administrators" -ErrorAction SilentlyContinue

(Start-Process "msiexec.exe" -ArgumentList "/i C:\Packages\Plugins\SupportFiles\WebStore8\WstSetup_64.msi DATACENTER=""DC1"" CONFIGSERVERS=""BAYTWSSQLWAW101"" ADDLOCAL=""ManagedClient,WstMonitoringAgent"" /lv C:\WSTClient.log /quiet" -NoNewWindow -Wait -PassThru).WaitForExit()

}

function Convert-StaticIP
{
$adapters = gwmi -cl win32_networkadapterconfiguration | ? {($_.ipaddress) -and $_.dhcpEnabled -eq 'True' }

foreach ($adapter in $adapters) {

  # Get original settings
  
  $ipAddress = $adapter.IPAddress

  $subnetMask = $adapter.IPSubnet

  $dnsServers = $adapter.DNSServerSearchOrder

  $defaultGateway = $adapter.DefaultIPGateway
  

  # Set to static and set dns and gateway:

  $adapter.EnableStatic($ipAddress,$subnetMask)

  $adapter.SetDNSServerSearchOrder($dnsServers)

  $adapter.SetGateways($defaultGateway)

  Clear-DnsClientCache
  Shutdown /r /f /t 60
  }
}
ConfigureEventLog
DiskConfiguration
Add-FirewallRules
Set-TimezonetoPST
InstallGenevaAgent


if ($Role -eq 'SQL')
{
    AddFirstSQLAdmin
    DriveCheck('D:')
    DriveCheck('E:')
    DriveCheck('H:')
    DriveCheck('O:')
    DriveCheck('T:')
    ConfigureStartupPath
    ConfigureDataPath
    ConfigureLogPath
    ConfigureTempdbPath
    ConfigurebackupPath
    ConfigureErrorPath
    ConfigureServerLoginMode
    ConfigureMaxDop
    ConfigureDefaultLocations
    ConfigureMaxMemory
    ConfigureSQLAgent
    MoveMasterFiles
    MoveModelFiles
    MoveMSDBFiles
    ConfigureModelDataFile
    ConfigureModelLogFile
    ConfigureMSDBDataFile
    ConfigureMSDBLogFile
    ConfigureAuditing
    ConfigureBuiltInAdmins
    MoveTempdbFiles
    AddTempdbFiles
    ConfigureTempDataFile
    ConfigureTempLogFile
    ConfigureMasterDataFile
    ConfigureMasterLogFile
    ConfigureStartupJob
    ConfigureExtendedSprocs
    #ConfigureSQLAccount
    ConfigureSQLServerService
    ConfigureSQLAgentService
    ConfigureLocalPolicy
    EnableMSDTC
    twswebstore
}


if ($Role -eq 'Web')
{
DriveCheck('D:')
DriveCheck('E:')
enableIIS
RemoveDefaultWebsite
}

#Convert-StaticIP
