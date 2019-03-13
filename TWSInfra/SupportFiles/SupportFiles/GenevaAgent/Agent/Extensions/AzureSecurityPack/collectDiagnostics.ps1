<#----------------------------------------------------------------------------------------------------------------------------------- 
:: <copyright file="collectDiagnostics.ps1" company="Microsoft">
::     Copyright (c) Microsoft Corporation.  All rights reserved. 
:: </copyright> 
:: 
:: <summary> 
:: Tool to collect Diagonostic Data specific to AzSecPack.
:: </summary>
:: ----------------------------------------------------------------------------------------------------------------------------------

::------------------------------------------------------------------------------------------------------------------------------------
::	 												collectDiagnostics.ps1
::------------------------------------------------------------------------------------------------------------------------------------
::-- Tool to collect Diagonostic Data specific to ASM.
::-- This tool can be either run via command line manually
::-- or using some other process to launch it, it gets 
::-- all the logs/relevant information needed to determine
::-- what might be wrong on a particular node.
::-- Usage : 
::--	(i).\collectDiagnostics.ps1 <path to Monitoring Data Directory> 
::--    (ii).\collectDiagnostics.ps1 -monitoringPath <path to Monitoring Data Directory> -readLogPath <path to log file Directory> 
::--                                 -outputLogPath <path to output Directory>
::--        readLogPath and outputLogPath are not mandatory
::-- 1. Cleans up the diagnosticsData directory if exists else creates one
::-- 2. Collects all the logs and copies them to the diagnosticsData dir:
::--	a. List of all processes running on the system in : tasklist.txt
::--	b. Gets the list of all publishers on the machine in : AllPublishers.txt
::--	c. Executes command "wevtutil gp Microsoft-Azure-Security-Scanner" 
::--		and the output is copied to : ASMPublisher.txt
::--	d. Checks whether the Antimalware engine is running; executes command
::--		"sc query msmpsvc" and copies output to msmpsvc.txt 
::--	e. Executes command "wevtutil gp Microsoft-Windows-AppLocker" 
::--		and the output is copied to : AppLockerPublisher.txt
::--    f. Copies local AppLocker events from all four Applocker channels into diagnostics data directory 
::--    g. Gets local and effective AppLocker policy in xml format and copies policy to AppLockerLocalPolicy.xml and AppLockerEffectivePolicy.xml
::-- 	h. Copies the contents of <MonitoringDataDirectory>/Packages,Configurations,Packets to diagnosticsData dir
::--	i. Converts Scanner specific MA tables AsmScannerData/AsmScannerDefaultEvents/AsmScannerStatusEvents/TraceEvents from tsf to CSV
::-- 		and copies the corresponding CSV files as is to the dataDiagnostics dir.
::--	j. Converts AppLocker specific MA tables AppLockerEXEDLL/AppLockerMSISCRIPT/AppLockerPKGAPPDEPLOY/AppLockerPKGAPPEXEC from tsf to CSV
::-- 		and copies the corresponding CSV files as is to the dataDiagnostics dir.
::--    k. Copy all the *.log, *xml, *.json, *er files from current dir, readLogPath, $env:APPDATA\AzureSecurityPack, $env:TEMP\AzureSecurityPack 
::--        to $outputLogPath\currentDir, $outputLogPath\specifiedDirLog, $outputLogPath\appdataLog, $outputLogPath\tempLog.
::--    l. Get SecurityScanMgr and MonAgentHost process details and log to SecurityScanMgrProcessInfo.log and MonAgentHostProcessInfo.log;
::--    m. Status of copying table and logs are in copyTableStatus.log, copyLogStatus.log and collectDiagnosticsStatusLog.log
::-- ******************************************************************************************************************************************
::-- 3.	Once all the relevant information is copied over to the dataDiagnostics dir,  
::--	we zip it : %computername%_diagnosticsData_%currentDate%_%currentTime%.zip
::-- 4. This zip file can be pulled to get all the relevant diagnostic data from a particular node.#>

Param([Parameter(Mandatory=$true)]
      [string] $monitoringPath = "", 
      [string] $readLogPath = "",
      [string] $outputLogPath = "")

$logFile = "collectDiagnosticsStatusLog.log"
# Set up output path
if ($outputLogPath = "") { 
    $outputLogPath = $env:SystemDrive;   
}

$outputPath = "$outputLogPath\diagnosticsData";
$zipDir = "$outputLogPath\DiagnosticsZipDir";

$currentDate = (Get-Date).ToString("MMddyyyy");
$currentTime = (Get-Date).ToString("HHmm");
$computerName = $env:COMPUTERNAME;
$zipPath = $zipDir + "\" + $computerName + "_diagnosticsData_" + $currentDate + "_" + $currentTime + ".zip";

# Helper function
# Set file/dir inheritance to false and remove user access
Function SetFilePermission (
		[parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$path
	)
{
    icacls $path /inheritance:d /T;
	icacls $path /remove:g Users /T;
}

# Helper function
# Get Process id, image path, args and EnvironmentVariables for a process
Function GetProcessDetail(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$processName
    ){

    $processActive = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if($processActive -eq $null) {
        Write-Output "Process $processName not Found"
    }else { 
        Write-Output "Get infomation for process $processName :"
        $processDetails = Get-Process -Name $processName;
        foreach ($processDetail in $processDetails) { 
            Write-Output "PID = " $processDetail.Id;
            Write-Output "ImagePath = " $processDetail.Path;
            $startInfo = $processDetail.StartInfo;
            Write-Output "Args = "
            foreach($arg in $startInfo.Arguments) {
                Write-Output $arg;
            }
            Write-Output "EnvironmentVariables ="
            foreach ($envVaribable in $startInfo.EnvironmentVariables.Keys) {
                $value = $startInfo.EnvironmentVariables[$envVaribable];
                Write-Output "$envVaribable : $value";
            }            
        }
    }
}

# Helper function
# Convert tsf to csv and copy it to output path
Function ConvertAndCopyTablesAzSecPack (
		[parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$tablePath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$table2CSVPath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$tsfFileList
	){

    Tee-Object $outputPath\$logFile -Append -InputObject "ConvertAndCopyTablesAzSecPack function called the table path passed as an argument is $tablePath and table2csv path is $table2CSVPath" | Write-Host
	Tee-Object $outputPath\$logFile -Append -InputObject "The outputpath is $outputPath" | Write-Host
	Tee-Object $outputPath\$logFile -Append -InputObject "The table2csvpath is $table2CSVPath" | Write-Host
    
    foreach ($tsfFile in $tsfFileList) {
        if (Test-Path "$tablePath\$tsfFile.tsf") {
            Tee-Object $outputPath\$logFile -Append -InputObject "Found $tablePath\$tsfFile.tsf trying to convert it to CSV and copying to diagnosticData directory." | Write-Host
            Tee-Object $outputPath\$logFile -Append -InputObject "The command is $table2CSVPath\table2csv.exe $tablePath\$tsfFile.tsf" | Write-Host		    
		    & $table2CSVPath\table2csv.exe $tablePath\$tsfFile.tsf
		    robocopy $tablePath $outputPath "$tsfFile.csv" /log+:$outputPath\copyTableStatus.log /tee
	    }else{
            Tee-Object $outputPath\$logFile -Append -InputObject "$tablePath\$tsfFile.tsf not found." | Write-Host
        }
    }    
}

if (Test-Path $outputPath) {
   Remove-Item -r $outputPath;        
}

New-Item $outputPath -type directory;
SetFilePermission -path $outputPath;      

if (Test-Path $zipPath) {
    Remove-Item -r $zipPath;
}

if ((Test-Path $zipDir) -eq $false) {
    New-Item $zipDir -type directory;  
    SetFilePermission -path $zipDir;
}

Tee-Object $outputPath\$logFile -Append -InputObject "Collect the list of processes running on the system right now at : $outputPath\tasklist.txt." | Write-Host
tasklist > $outputPath\tasklist.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Collect the list of all the Publishers on this node at : $outputPath\AllPublishers.txt." | Write-Host
wevtutil ep > $outputPath\AllPublishers.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the Security-Scanner Publisher exists; results at : $outputPath\ASMPublisher.txt." | Write-Host
wevtutil gp Microsoft-Azure-Security-Scanner > $outputPath\ASMPublisher.txt 2>&1

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the Microsoft AntiMalware engine is running on the system; result at : $outputPath\msmpsvc.txt." | Write-Host
sc query msmpsvc > $outputPath\msmpsvc.txt 2>&1

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the AppLocker Publisher exists; results at : $outputPath\AppLockerPublisher.txt." | Write-Host
wevtutil gp Microsoft-Windows-AppLocker > $outputPath\AppLockerPublisher.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Copy AppLocker event files to $outputPath" | Write-Host
wevtutil epl "Microsoft-windows-AppLocker/EXE and DLL" $outputPath\AppLockerEXEDLL.evtx
wevtutil epl "Microsoft-Windows-AppLocker/MSI and Script" $outputPath\AppLockerMSISCRIPT.evtx
wevtutil epl "Microsoft-Windows-AppLocker/Packaged app-Deployment" $outputPath\AppLockerPKGAPPDEPLOY.evtx
wevtutil epl "Microsoft-Windows-AppLocker/Packaged app-Execution" $outputPath\AppLockerPKGAPPEXEC.evtx

Tee-Object $outputPath\$logFile -Append -InputObject "Get local AppLocker policy; results at : $outputPath\AppLockerLocalPolicy.xml." | Write-Host
Get-AppLockerPolicy -Local -Xml > $outputPath\AppLockerLocalPolicy.xml

Tee-Object $outputPath\$logFile -Append -InputObject "Get effective AppLocker policy; results at : $outputPath\AppLockerEffectivePolicy.xml." | Write-Host
Get-AppLockerPolicy -Effective -Xml > $outputPath\AppLockerEffectivePolicy.xml

# Copy Configuration, Package and Packets dir under monitoringPath to outputPath
if (($monitoringPath -eq "") -or ((Test-Path $monitoringPath) -eq $false)) {
    Tee-Object $outputPath\$logFile -Append -InputObject "The monitoring data directoiry is not specified or doesn't exist." | Write-Host
}else {
    if (Test-Path $monitoringPath\Configuration) {
        robocopy $monitoringPath\Configuration $outputPath\Configuration /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Configuration directory under monitoring data directory not found." | Write-Host
    }

    if (Test-Path $monitoringPath\Package) {
        robocopy $monitoringPath\Package $outputPath\Package /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Package directory under monitoring data directory not found." | Write-Host
    }

    if (Test-Path $monitoringPath\Packets) {
        robocopy $monitoringPath\Packets $outputPath\Packets /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Packets directory under monitoring data directory not found." | Write-Host
    }
}
    
# Convert and copy tables under monitoringPath to output path
$tablePath = "$monitoringPath\Tables";
$currentPath = split-path -parent $MyInvocation.MyCommand.Definition;
$table2CSVPath = (get-item $currentPath).parent.parent.FullName;
$tsfFileList = "AsmScannerData", "AsmScannerDefaultEvents", "AsmScannerStatusEvents", "TraceEvents", "MAEventTable", "AppLockerEXEDLL", "AppLockerMSISCRIPT", "AppLockerPKGAPPDEPLOY", "AppLockerPKGAPPEXEC";

ConvertAndCopyTablesAzSecPack -tablePath $tablePath -table2CSVPath $table2CSVPath -tsfFileList $tsfFileList

# Copy all log, er, json and xml files from current dir, specified dir, $env:APPDATA\AzureSecurityPack and $env:TEMP\AzureSecurityPack to output path
Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in current directory to $outputPath\currentDirLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $currentPath $outputPath\currentDirLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee

if ($readLogPath -eq "" -or (Test-Path $readLogPath) -eq $false) {
    Tee-Object $outputPath\$logFile -Append -InputObject "readLogPath not specified or not found" | Write-Host
}else {
    Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in specified directory $readLogPath to $outputPath\specifiedDirLog, and status to $outputPath\copyLogStatus.log" | Write-Host
    robocopy $readLogPath $outputPath\specifiedDirLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee
}

Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in $env:APPDATA\AzureSecurityPack to $outputPath\appdataLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $env:APPDATA\AzureSecurityPack $outputPath\appdataLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee

Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in $env:TEMP\AzureSecurityPack to $outputPath\tempLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $env:TEMP\AzureSecurityPack $outputPath\tempLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee


# Get SecurityScanMgr and MonAgentHost process details and log to $outputPath
GetProcessDetail -processName SecurityScanMgr >> $outputPath\SecurityScanMgrProcessInfo.log;
GetProcessDetail -processName MonAgentHost >> $outputPath\MonAgentHostProcessInfo.log;

# Zip all files
Set-Content -path $zipPath -value ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18)) -ErrorAction Stop
$zipfile = $zipPath | Get-Item -ErrorAction Stop
$zipfile.IsReadOnly = $false  
#Creating Shell.Application
$shellApp = New-Object -com shell.application
$zipPackage = $shellApp.NameSpace($zipfile.fullname)
$target = Get-Item -Path $outputPath
$zipPackage.CopyHere($target.FullName)
# SIG # Begin signature block
# MIIkZQYJKoZIhvcNAQcCoIIkVjCCJFICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAi9w2dFgg6nz2b
# 7vV6PE1sOz4QfSrG5RJw8BY8UcHWsaCCDXYwggX0MIID3KADAgECAhMzAAABApvw
# C6eOXcNNAAAAAAECMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTgwNzEyMjAwODQ4WhcNMTkwNzI2MjAwODQ4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUDAYEhQiWKKfpa3TQ4mGT46UwX/UIw1uE9sGnMPeISoedadT4fvCy8/PZRrTh
# ZBX9b57KFsdYqKOZjNWn/PGNGndg7F1FC8ebalEJhAOS5BBqqPtyOA06BMewVkEv
# TJSrsMDIoi+f0fMD2QkBpQuo3RWmXmIooaqu29rVRJqjCTLZxSva7CttEYz10R2a
# c3D/mvjopbp0qOp2c3vVlvAYuCfM6O2URhG4aZeV+JizcZgx7nvYu3W1OV8iZHkN
# WeqmhDjx+o9jl6xUF7rJnT9lLTeX6n5wHJnl2uPqbj7XJRzfGASda+BDhGNvBUix
# uV08JmisMcr9fu7u2ttsRsNbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiRcFro07Z+9cIaFfJbDdSbk3Tu8w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQzNzk2NDAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJP2AnJLtJYleQ4Y+xu0
# mJhorCOZ5ethfBHgoSMAyX7zSSjgdf3zaMQZxqBWVWoiuzVVJRvBZnJzp2IitEFu
# hzB6LGOkJi1/+UCxeHnFw/V7jaHn6EBWZ3k1BHZgJleNNhmSLZvYbdBBSsVM1x3H
# dvJ6sz8lE4+N2yvXTxTJwmWKoxu53+LEGFgFrPHtDEvn5IR/RGLLZqKSKrfIkXNK
# PPuLpyr/4mG0EVkB14trliGGrUZu26qZX7HwYOjo+DkqEkZWe1l7fA0C9ZwCFLYV
# /Gdb/7Ior5ARqTh89EV/IB/0K79VyS3VY1PA6xegIIuYGOVX9QKUMoQSbzpQb/XW
# hRLntzMDwcVHMPaHj/x/iQpiGaUTSMsPPl+UgFZZMLPTyHT6ID3OMYhuWrDcxuTI
# r1MIqCpZObp6ulQ9MIM9QZlt1s/Y6LAlpDzUi+YrVRR6PpqROT+MfrtXhJUQJkPC
# ZoTcK5kjzE1PJfHQQDlJ7z8t0VGyPgu9KtQ9oW/1cKmfa1WZQSlpElOoS/NT4si2
# UTf9a787z68X7IJ4cKEnAHj0U7PhyZFJ5sC0z5vZMWVbQJcE6DgBk+IJxyv7+b8I
# fgKTnryEQDxLwmX87vU2FCU1a4sxJEAlVAOkZkez0CO2jxfJsO9gciiEJOCoCDcK
# 7pzYBx6Fi5zPFJ+h5pLv1XWHMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCFkUwghZBAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAECm/ALp45dw00AAAAAAQIwDQYJYIZIAWUDBAIB
# BQCggcYwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGWvQno/CJ986HIYh2jwdF43
# bks1r4mcSiYh3HTeXyN9MFoGCisGAQQBgjcCAQwxTDBKoCSAIgBNAGkAYwByAG8A
# cwBvAGYAdAAgAFcAaQBuAGQAbwB3AHOhIoAgaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3dpbmRvd3MwDQYJKoZIhvcNAQEBBQAEggEAFx7NPkJS4yim4VJfPEMGJhXK
# nEKsT57MFH6s2y+MAUSvmNUegfrw4gvSqt590uDDr/sOv+819mW9L0LHwKiII3bo
# su88A2XwAsjjtIOViHHIDBCg3oFgtf15h67V+wwJSWBKMxPeKaBjQWtsQGBuWq9L
# MtGMNZssfOURjK77ULl75S94hewATCA0KP7xrJsVT0pAgQ+XAqYwnAGN9ur6QMg7
# WtvlfY1W0kBC8iVFm2w05J9fO72QTgopN+F64Wdt763q0EGqDhcT/eooZOWa5uTq
# xSWbvH6Dugd1zptzTcwdTSYeEQ+SpS8maqu4ggBcxeR6EOkuxMPHMGuU4LgclqGC
# E7cwghOzBgorBgEEAYI3AwMBMYITozCCE58GCSqGSIb3DQEHAqCCE5AwghOMAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcEggFDMIIBPwIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDdlzCZOBakf5z32iIQG0IT
# kAS99SxdfA4aLw15TIgnjwIGW9uby4KdGBMyMDE4MTEyMjA1MDk1My4yMDFaMAcC
# AQGAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0QyRS0zNzgyLUIwRjcxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg8fMIIGcTCCBFmgAwIBAgIK
# YQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0
# NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX7
# 7XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM
# 1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHP
# k0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3Ws
# vYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw
# 6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHi
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVt
# VTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGS
# MIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4y
# IB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAu
# IB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+
# zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKK
# dsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/Uv
# eYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4z
# u2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
# bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlX
# dqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHh
# AN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A
# +xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdC
# osnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42ne
# V8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nf
# j950iEkSMIIE9TCCA92gAwIBAgITMwAAAM9MEKXbLLcFUgAAAAAAzzANBgkqhkiG
# 9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xODA4MjMy
# MDI2MjdaFw0xOTExMjMyMDI2MjdaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0QyRS0zNzgyLUIwRjcx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzHxlarCT2EWGZ1XQCfpDdTwgyPVNmHk86
# 7Oo2E7ACZfzRs2POFstW2dOWSJWHTkZQkBlL6eKKVoy5A2zEZu/RN6FDFG0Q7DwK
# 48b+F8iY24MLMnCvkxrQxlnnx3xbN/qBsy5p7QLCn+JRGuiK+aPSVWM4VLT4oeS8
# 8zKQ6ag73+7a3dNV0ngNmjgTVGTY+XXAit/KjYvPW8dlv04XPJFm/cy8KC7W8JGJ
# 5SO6NarO5oUK42UKxx650bMt4cK29EGqxahUSPyi2ixkeoD5TRucNiXc7Yy4tuZe
# iLGrO2hhmi0R/UdgAMmcvZHRcYKSFvdYYQ1BOfSSBcDjHcuPYBwxAgMBAAGjggEb
# MIIBFzAdBgNVHQ4EFgQU4WJs4yK2OkCyZhvi0PsT3rbHy/AwHwYDVR0jBBgwFoAU
# 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIw
# MTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0w
# Ny0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAQEAERI94KyQ4n8kNsTyMFtRlJykfui6PdbSLqX/MKv1/0PD
# NtypsrgUstwYt0cmkJ+WuEcwTkq9WrJYJ/joqAitahf2IRugw2Wj/Re5sRziqWSF
# zINayFecBw3d+oZPgUl6xGrekD8bOjNM7KfCJW0kjfM6kzIXHJXeB8aeSLH0lFAm
# ZsX5cCIahLqI/lGTFTuMe45z+vQV5JjgIxEKu7nzgEF4896hE7bQK8wqwY9et/d7
# feImM0tyLWrlKGKs+3uYOnz6wPr3WGPsd/iEQPR4HpWN4arfaKuqywyR4Abqz3tS
# Nm1lqXFn7r/JAFYvnubK7KLQOvz1QmQ4D9D8CRnbFKGCA60wggKVAgEBMIH+oYHU
# pIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYD
# VQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046N0QyRS0zNzgyLUIwRjcxJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2WiJQoBATAJBgUrDgMCGgUAAxUAiT7Q5NAyw4Vd
# XSKWst4t0a+4l92ggd4wgdukgdgwgdUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMScwJQYDVQQLEx5uQ2lwaGVyIE5UUyBFU046NTdGNi1DMUUwLTU1NEMx
# KzApBgNVBAMTIk1pY3Jvc29mdCBUaW1lIFNvdXJjZSBNYXN0ZXIgQ2xvY2swDQYJ
# KoZIhvcNAQEFBQACBQDfoHadMCIYDzIwMTgxMTIyMDAyODEzWhgPMjAxODExMjMw
# MDI4MTNaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAN+gdp0CAQAwBwIBAAICCI4w
# BwIBAAICGr4wCgIFAN+hyB0CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAaAKMAgCAQACAxbjYKEKMAgCAQACAwehIDANBgkqhkiG9w0BAQUFAAOCAQEA
# pKr6a+BCitAIE19U4d9U+NbAJ2eb75TTlS3tlTZZ9YO3dYDef7VQl6jpfOlr3B4T
# nVRRze4XDjCS9nVdBoRASnVVIuH5u9YDesYjtuGxit2WsuZeRRYUJXuiUJDotHcd
# iyelGsVQWfZoilY7eWS29z0WvZbtxAOF4ULw1wvp0k71df3IzzHScnTtUQ1iBDbG
# LvbXS5MKJ6DXNj4mfh+pyXw4UIgF7P75mbGFG+O0indzxXPJbbtXIFgWrvzfDrgj
# xjHIBlfWUTgtaMT+yxMFC5uXiPyO+Bio/wgo+ZCHwl67kcD1RvKALSS9g56SWI2s
# p5DspMPWcervNT5c28EcZDGCAvUwggLxAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAAAz0wQpdsstwVSAAAAAADPMA0GCWCGSAFlAwQCAQUA
# oIIBMjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIE
# IEuFCEJK6Rcw+kBHo/yeC4fK+7x8/2kUiZ005kSkYrdKMIHiBgsqhkiG9w0BCRAC
# DDGB0jCBzzCBzDCBsQQUiT7Q5NAyw4VdXSKWst4t0a+4l90wgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAM9MEKXbLLcFUgAAAAAAzzAW
# BBT8NWVZU/0W/c65bjwViF0OZ8fDJzANBgkqhkiG9w0BAQsFAASCAQAymUXj0k8d
# YIiDlnYzXu4kMsvMCExGLw7dJAH9NDpphTCljKeEXSbXmFUPExuObrYi/kEcSoWg
# kS/vvUv1uNYsLWfvzrciEgHgILvA+lbok1o54hNWzA7gKP6tQy4az+c/dUx+DD6L
# o+A+ruTQj46cdUTpV+0Pp+Vc3NJbCNWFzpcpzhMNPGMi8dH5t3BoUE5WsPzROFC0
# 4KIsTSHK7H6zOaMlthDG+SjnMQWvsiDS2f7E/T2LdSOIYOJtXL8uZ95r2pLlyqrF
# 6Rhvp6GCaezRBDiJ92mRb1DSy6hpBd8//SS2X3P/LxX4cdc3PJGfBebxbUodAVR4
# w8IxCQWNLvK3
# SIG # End signature block
