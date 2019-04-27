
param (
    [string]$Username,
    [string]$Password,
    [string]$Role,
    [string]$xpertenvName,
    [string]$xpertRole,
    [string]$xpertServiceKey

)

$SupportFilesURL="https://raw.githubusercontent.com/MSTWS/TWSArm/master/MDOLLAR/SupportFiles/SupportFiles.zip"

function Write-FileLog
{
param
(
[string] $message
)
$logfilename="C:\WindowsAzure\Logs\TWSCustomInstallLog.txt"
Write-Output $message | Out-File -FilePath $logfilename -Append -Force
}

sleep 120
$WebClient = New-Object System.Net.WebClient
Write-FileLog("Downloading SupportFiles.Zip...")
#RoboCopy "\\BAYTWSSQLWAW101\ScriptsandExecutables" C:\Packages\Plugins SupportFiles.zip /XN
$WebClient.DownloadFile($SupportFilesURL,"C:\Packages\Plugins\Supportfiles.zip")

Sleep 10
Write-FileLog("Extracting SupportFiles.Zip to C:\Packages\Plugins...")
Expand-Archive C:\Packages\Plugins\SupportFiles.zip -DestinationPath C:\Packages\Plugins\SupportFiles

Write-FileLog("Converting $UserName and password to Credential...")
$pass = ConvertTo-SecureString -AsPlainText $Password -Force

$SecureString = $pass
$username=$env:COMPUTERNAME+"\"+$Username
# Users you password securly
$MySecureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$SecureString


$Logininfo="Executing as " + $env:UserDomain + "\" + $env:UserName + " on " + $env:ComputerName
Write-Host $Logininfo
Write-FileLog -message $Logininfo
Write-FileLog("Calling AppConfiguration in context of $env:UserName")
Write-FileLog("Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $MySecureCreds -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role,$xpertenvName,$xpertRole,$xpertServiceKey")



Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $MySecureCreds -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role,$xpertenvName,$xpertRole,$xpertServiceKey
#Invoke-Command -ComputerName $env:COMPUTERNAME -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role,$xpertenvName,$xpertRole,$xpertServiceKey


Write-FileLog("Completed Post Deploy Activities...")