
param (
    [string]$Username,
    [string]$Password,
    [string]$Role,
    [string]$xpertenvName,
    [string]$xpertRole,
    [string]$xpertServiceKey

)

Start-Transcript -Path "C:\WindowsAzure\Logs\TWSCustomInstallLog.txt"

$SupportFilesURL = "https://vmext.file.core.windows.net/templates/SupportFiles/SupportFiles.zip?sv=2018-03-28&ss=bfqt&srt=sco&sp=rwdlacup&se=2019-12-31T17:07:45Z&st=2019-03-18T09:07:45Z&spr=https&sig=b3Cx5lnZi9USBJE%2Ft894m%2FV%2F4m4TSlFMomx8b2ablls%3D"

$AppConfigurationScriptURL = "https://vmext.file.core.windows.net/templates/SupportFiles/AppConfiguration.ps1?sv=2018-03-28&ss=bfqt&srt=sco&sp=rwdlacup&se=2019-12-31T17:07:45Z&st=2019-03-18T09:07:45Z&spr=https&sig=b3Cx5lnZi9USBJE%2Ft894m%2FV%2F4m4TSlFMomx8b2ablls%3D"

New-item -Path "C:\Packages\Plugins\" -ItemType Directory -Force -ErrorAction Ignore

Write-Output "Downloading SupportFiles.Zip..."
#RoboCopy "\\BAYTWSSQLWAW101\ScriptsandExecutables" C:\Packages\Plugins\SupportFiles.zip /XN
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($SupportFilesURL, "C:\Packages\Plugins\Supportfiles.zip")

Start-Sleep -Seconds 5
Write-Output "Extracting SupportFiles.Zip to C:\Packages\Plugins..."
Expand-Archive C:\Packages\Plugins\SupportFiles.zip -DestinationPath C:\Packages\Plugins\SupportFiles -Force

if(Test-Path C:\Packages\Plugins\SupportFiles)
{
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($AppConfigurationScriptURL, "C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1")
    Write-Output "Is this script running with elevated privileges ?"

    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    Write-Output "Converting $UserName and password to Credential..."
    $pass = ConvertTo-SecureString -AsPlainText $Password -Force

    $SecureString = $pass
    # Users you password securly
    $MySecureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecureString

    Write-Output "Calling AppConfiguration.ps1..."
    Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $MySecureCreds -FilePath 'C:\Packages\Plugins\SUpportFiles\AppConfiguration.ps1' -ArgumentList $Role, $xpertenvName, $xpertRole, $xpertServiceKey
    Write-Output "Completed Post Deploy Activities..."
}

Stop-Transcript