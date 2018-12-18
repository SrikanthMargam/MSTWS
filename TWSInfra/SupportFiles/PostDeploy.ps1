
param (
    [string]$Username,
    [string]$Password,
    [string]$Role,
    [string]$xpertenvName,
    [string]$xpertRole,
    [string]$xpertServiceKey

)


function Write-FileLog
{
param
(
[string] $message
)
$logfilename="C:\WindowsAzure\Logs\TWSCustomInstallLog.txt"
Write-Output $message | Out-File -FilePath $logfilename -Append -Force
}



Write-FileLog("Copying SupportFiles.Zip...")
Copy-Item -Path "\\BAYTWSSQLWAW101\ScriptsandExecutables\SupportFiles.zip" -Destination C:\Packages\Plugins -Force
Sleep 5
Write-FileLog("Extracting SupportFiles.Zip to C:\Packages\Plugins...")
Expand-Archive C:\Packages\Plugins\SupportFiles.zip -DestinationPath C:\Packages\Plugins\SupportFiles

Write-FileLog("Converting $UserName and password to Credential...")
$pass = ConvertTo-SecureString -AsPlainText $Password -Force

$SecureString = $pass
# Users you password securly
$MySecureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$SecureString

Write-FileLog("Calling AppConfiguration.ps1...")
Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $MySecureCreds -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role
Write-FileLog("Completed Post Deploy Activities...")

