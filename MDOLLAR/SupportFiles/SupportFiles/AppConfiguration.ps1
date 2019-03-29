param
(
[string]$Role,
[string]$XpertTWSEnvName,
[string]$XpertROle,
[string]$xpertservicekey
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


function SecureStringTotext($encrypted) 
{
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encrypted)       
return $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
}

function Install-Antivirus
{
try
{
Write-FileLog -message "Setting up Antivirus Software"
$ExePath = "C:\Packages\Plugins\SupportFiles\SystemCenter\SCEPInstall.exe"
#$ExePath = "C:\Test\SCEPInstall.exe"
& $ExePath  /q /s
Write-FileLog -message "Completed Antivirus Installation"
}
Catch [Exception]
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host "Error Occured on Install-Antivirus Method : $ErrorMessage - $FailedItem"
    Write-FileLog -message "Error Occured on Install-Antivirus Method : $ErrorMessage - $FailedItem"
    Break

}
}
function InstallXpertAgent
{
try
{
Write-FileLog -message "Installing xpert"
$scriptPath = "C:\Packages\Plugins\SupportFiles\InstallNonAPXpertAgent"
$DestinationPath="E:\XpertAgent"
$zipPAth=$ScriptPath + "\NonAPXpertBinaries.zip"
Write-FileLog -message "Stopping Xpert Agent if any"
Stop-Process -Name Xpert.Agent* -Force -ErrorAction Continue
Write-FileLog -message "Unzip Xpert Agent to destination location"
Expand-Archive $zippath -DestinationPath $DestinationPath -Force
$appDir = “$DestinationPath\app”
$dataDir = “$DestinationPath\data”
Write-FileLog -message "Setting up Environment Variables"
[Environment]::SetEnvironmentVariable(“APPDIR”, $appDir,[EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable(“DATADIR”, $dataDir,[EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable(“XPERT_AGENT_INSTALL_LOCATION”, “$appDir\XpertAgent”,[EnvironmentVariableTarget]::Machine)

Write-FileLog -message "Setting up Permissions for Network Service"
icacls $appDir /grant "NETWORK SERVICE:(OI)(CI)F"
icacls $dataDir /grant "NETWORK SERVICE:(OI)(CI)F"

Write-FileLog -message "Updating Config Files"
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

Write-FileLog -message "Setting up Task Scheduler Tasks"
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
Write-FileLog -message "Completed Xpert Installation"
}
Catch [Exception]
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host "Error Occured on Xpert Installation Method : $ErrorMessage - $FailedItem"
    Write-FileLog -message "Error Occured on Install-Antivirus Method : $ErrorMessage - $FailedItem"
    Break

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
New-Partition -DiskNumber 5 -DriveLetter I -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Log' -Confirm:$false
Write-FileLog -message "I:\ Created"
}
6
{
New-Partition -DiskNumber 6 -DriveLetter O -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Tempdb' -Confirm:$false 
Write-FileLog -message "O:\ Created"
}
7
{
New-Partition -DiskNumber 7 -DriveLetter T -UseMaximumSize  | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Tempdb' -Confirm:$false 
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
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host "Error Occured on Install-Antivirus Method : $ErrorMessage - $FailedItem"
    Write-FileLog -message "Error Occured on Install-Antivirus Method : $ErrorMessage - $FailedItem"
    Break

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


Function Set-TimezonetoPST
{
Write-FileLog -message "-----Begin-Set-Timezone------"
Write-FileLog -message "Updating Server Timezone to PST"
Set-TimeZone -Name "Pacific Standard Time"
Write-FileLog -message "-----End-Set-Timezone------"
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
$Logininfo="Executing as " + $env:UserDomain + "\" + $env:UserName + " on " + $env:ComputerName
Write-Host $Logininfo
Write-FileLog -message $Logininfo

DiskConfiguration
InstallXpertAgent
Install-Antivirus