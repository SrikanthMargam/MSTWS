
#Template Location
$sqlTemplate="https://raw.githubusercontent.com/MSTWS/TWSArm/master/TWSInfra/Templates/sql-vm-deploy.json"
$webTemplate="https://raw.githubusercontent.com/MSTWS/TWSArm/master/TWSInfra/Templates/web-vm-deploy-old-v1.json"
#$webTemplate="https://raw.githubusercontent.com/MSTWS/TWSArm/master/TWSInfra/Templates/web-vm-deploy.json"

#PARAMETER HELP
#$Role : "SQL" oR "WEB"
#$DC :  "DC1" or "DC2" or "DC3"  [DC1-West US, DC2 - East US, DC3 - North Europe]
#StackCode: "XXX" - Any 3 Letter String. THIS WILL BE APPENDED ON VM NAME, AVSET Etc.
#StartCounter: nnn - Any 3 Digit Number > 100
#NumberofServers=n - Number of VM's you need to Spin up
#$SKU : "Standard_DS12_v2" or "Standard_DS13_v2" or "Standard_DS14_v2" or "Standard_G4"
#$StorageType : "Standard_LRS" or "StandardSSD_LRS" or "Premium_LRS"
#$DomainAccountName : Your PHX DOMAIN ACCOUNT eg: phx\rajeshbs

#DRIVE CONFIG HELP
#C & D FOR WEB & SQL. E,H,O,T for SQL ROLE ONLY
#MENTION SIZE IN GB - In this fashion: 32, 64, 128, 256, 512, 1024,2048,4095 

# BEGIN PARAMETERS
$Role="WEB"
$SubRole="WEB" 
$DC="POC" 
$StackCode="SRS"
$StartCounter=401
$NumberofServers=1
$CDrive=256
$DDrive=128
$EDrive=1024
$SKU="Standard_DS13_v2" 
$StorageType="Standard_LRS"
$DomainAccountName="phx\rajeshbs"
$DomainPassword = Read-Host -Prompt "Enter your DOMAIN Password for $DomainAccountName" -AsSecureString



#MENTION ONLY IF SQL SERVERS ELSE IGNORE
$HDrive=1024
$ODrive=256
$TDrive=256 

#DO NOT CHANGE THE BELOW VALUES. CONTACT RAJESHBS OR AJAYVEL FOR USING THE BELOW PARAMETERS.
$ServerName="BN2TWSFILOCO101"
$OverrideNamingRules=$false
#END OF PARAMETERS


#AUTOGENERATION 
$Domaintojoin="PHX.GBL"
$OUPath="OU=TWS-Services,OU=Resource,OU=Production,DC=phx,DC=gbl"
$LocalAdminName="twsadmin"
$LocalAdminSecuredPassword = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005c615ee69dea6b45a4c6d47c41dfe5c50000000002000000000003660000c000000010000000148436e954690b7dbea7d900f78c9f4b0000000004800000a000000010000000484cebe57940ce15323e5b1b75e520f220000000373ab78f30293f8da29923a9eda47351355f2e3f2659ab55c9f61c2342e1c417140000007317556ac035038ac14c55031319b98b27ded63b" | convertto-securestring 
$ServicePrefix=$StackCode + $DC

if ($OverrideNamingRules -eq $true)
{
$NumberofServers=1
}


Switch ($DC)
{
"DC0" 
{
#BAY DC
$XpertTWSEnvName="WindowsStore-Prod-BY2" #If Xpert Install these variable need to be paramterised.
$xpertservicekey="D156BF15F5C9CBC9819BF1CA10B2F75C96FD96B2D26A65FF1E6D3B2914F6993681608A0493381E3980640EB2C5F4168F817FD0EE796170E7652105B6311BB07D"

$VirtualNetworkName="TWS-VNET-WUS-PROD"
$VirtualNetworkResourceGroup="Hypernet-WUS-RG" 
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-WUS-RG"
$DCCode="BA3"

}
"DC1" 
{
#BAY DC
$XpertTWSEnvName="WindowsStore-Prod-BY2" #If Xpert Install these variable need to be paramterised.
$xpertservicekey="D156BF15F5C9CBC9819BF1CA10B2F75C96FD96B2D26A65FF1E6D3B2914F6993681608A0493381E3980640EB2C5F4168F817FD0EE796170E7652105B6311BB07D"

$VirtualNetworkName="TWS-VNET-WUS2-PROD"
$VirtualNetworkResourceGroup="Hypernet-WUS2-RG" 
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-WUS2-RG"
$DCCode="BY3"
}
"DC2" 
{

#BN1 DC
$XpertTWSEnvName="WindowsStore-Prod-BN1"
$xpertservicekey="EFE0145BE36396EEC5B7D9975CD46F8B1A4B577A7BE54BD3B4F209350A11057A0C545387E2875AF65A9BC5F1883FAF1FC5D8CF3EA211D700D820786526BDF207"
 
$VirtualNetworkName="TWS-VNET-EUS2-PROD"
$VirtualNetworkResourceGroup="Hypernet-EUS2-RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-EUS2-RG"
$DCCode="BN2"
}

"DC3" 
{ 
#DB3 DC
$XpertTWSEnvName="WindowsStore-Prod-DB3"
$xpertservicekey="8C3C556776EF51301B586C66B3B7B190A68C0CAF9294D015EFF3304FF042F22AA0380AE0E36368E24B0BEF2D366B8F8517EF82A59A5974DE1A0E3086137D587C"

$VirtualNetworkName="TWS-VNET-NEUR-PROD"
$VirtualNetworkResourceGroup="Hypernet-NEUR-RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-NEUR-RG"
$DCCode="DB5"
}
"POC" 
{ 
#BAY DC
$XpertTWSEnvName="WindowsStore-Prod-BY2" #If Xpert Install these variable need to be paramterised.
$xpertservicekey="D156BF15F5C9CBC9819BF1CA10B2F75C96FD96B2D26A65FF1E6D3B2914F6993681608A0493381E3980640EB2C5F4168F817FD0EE796170E7652105B6311BB07D"

$VirtualNetworkName="TWSHYPERNET-WUS2-1"
$VirtualNetworkResourceGroup="HypernetWUS2RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="UST-TWS-PROD-RG"
$DCCode="MWH"
}

}

Switch ($StackCode)
{
"WPW"
{
$XpertRoleName="AntiPiracyStack"
}
"WDW"
{
$XpertRoleName="AppCatalogReviewStack"
}
"BPB"
{
$XpertRoleName="BackEndPipeline"
}
"WIW"
{
$XpertRoleName="ClientInputStack"
}
"WTW"
{
$XpertRoleName="ComTransactionLicenseStack"
}
"WAW"
{
$XpertRoleName="ConfigStackPrimary"
}
"WSW"
{
$XpertRoleName="DataPresentationStack"
}
"WQW"
{
$XpertRoleName="EventQueueStack"
}
"WCW"
{
$XpertRoleName="IdentityCatalogConsumerStack"
}

"WLW"
{
$XpertRoleName="LPS"
}


"WCW"
{
$XpertRoleName="PipelineStack"
}

"ACP"
{
$XpertRoleName="PortalAppFabricCache"
}

"WPP"
{
$XpertRoleName="PortalDetailsStack"
}

"PRP"
{
$XpertRoleName="PortalFrontEndWeb"
}


"WSP"
{
$XpertRoleName="PortalStack"
}

"SLR"
{
$XpertRoleName="RemoteSigningFrontEndWeb"
}

"ACS"
{
$XpertRoleName="ServicesAppFabricCache"
}

"SMS"
{
$XpertRoleName="ServicesFESQLPipelinePrincipal"
}

"SRS"
{
$XpertRoleName="ServicesFrontEndWeb"
}

default
{
$XpertRoleName="NonAquaman"
}

}


for ($ctr=1; $ctr -le $NumberofServers; $ctr++)
{
if ($OverrideNamingRules -eq $true)
{
Write-Host "Print Hello"
$vmname=$ServerName
}
else
{
$vmname=$DCCode + "TWS" + $SubRole + $StackCode + $StartCounter
}
$StartCounter++
$DeploymentName=$vmname + "_Deployment"

Write-Host "Parameters: -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -Disk3-H-Drive $HDrive -Disk4-O-Drive $ODrive -Disk5-T-Drive $TDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword  -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey -AsJob"

Switch ($Role)
{

"SQL"
{
$templatepath=$sqlTemplate
New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -Disk3-H-Drive $HDrive -Disk4-O-Drive $ODrive -Disk5-T-Drive $TDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey  -AsJob
}
"Web"
{
$templatepath=$webTemplate
New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey -AsJob
}
}

}

