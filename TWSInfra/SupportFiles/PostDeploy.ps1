
param (
    [string]$Username,
    [string]$Password,
    [string]$Role,
    [string]$xpertenvName,
    [string]$xpertRole,
    [string]$xpertServiceKey

)
Write-Output "Code enter to PostDeployment script" | Out-File -FilePath "C:\WindowsAzure\Logs\MonitoringAgent.log" -Append -Force
function Write-FileLog
{
param
(
[string] $message
)
$logfilename="C:\WindowsAzure\Logs\TWSCustomInstallLog.txt"
Write-Output $message | Out-File -FilePath $logfilename -Append -Force
}
Write-Output "Code exited to file creation script" | Out-File -FilePath "C:\WindowsAzure\Logs\MonitoringAgent.log" -Append -Force

Write-FileLog("Downloading SupportFiles.Zip...")
RoboCopy "\\BY3TWSWEBUTL101\ScriptsandExecutables" C:\Packages\Plugins SupportFiles.zip /XN
#$WebClient.DownloadFile($SupportFilesURL,"C:\Packages\Plugins\Supportfiles.zip")

Sleep 5
Write-FileLog("Extracting SupportFiles.Zip to C:\Packages\Plugins...")
Expand-Archive C:\Packages\Plugins\SupportFiles.zip -DestinationPath C:\Packages\Plugins\SupportFiles

Write-FileLog("Converting $UserName and password to Credential...")
$pass = ConvertTo-SecureString -AsPlainText $Password -Force

$SecureString = $pass
# Users you password securly
$MySecureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$SecureString

Write-FileLog("Calling AppConfiguration.ps1...")
Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $MySecureCreds -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role,$xpertenvName,$xpertRole,$xpertServiceKey
Write-FileLog("Completed Post Deploy Activities...")

