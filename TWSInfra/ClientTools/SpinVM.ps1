
#Template Location
$sqlTemplate="https://raw.githubusercontent.com/MSTWS/TWSArm/master/TWSInfra/Templates/sql-vm-deploy.json"
$webTemplate="https://raw.githubusercontent.com/MSTWS/TWSArm/master/TWSInfra/Templates/web-vm-deploy.json"

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
$Role="SQL" 
$DC="POC" 
$StackCode="WAP"
$StartCounter=101
$NumberofServers=1
$CDrive=256 
$DDrive=128
$EDrive=512
$HDrive=512
$ODrive=512
$TDrive=256 
$SKU="Standard_DS12_v2" 
$StorageType="StandardSSD_LRS"
$DomainAccountName="phx\rajeshbs"
$DomainPassword = Read-Host -Prompt "Enter your PHX DOMAIN Password" -AsSecureString



#DO NOT CHANGE THE BELOW VALUES. CONTACT RAJESHBS OR AJAYVEL FOR USING THE BELOW PARAMETERS.
$ServerName=""
$OverrideNamingRules=$false
#END OF PARAMETERS


#AUTOGENERATION 
$Domaintojoin="PHX.GBL"
$OUPath="OU=TWS-Services,OU=Resource,OU=Production,DC=phx,DC=gbl"
$LocalAdminName="twsadmin"
$LocalAdminSecuredPassword = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005c615ee69dea6b45a4c6d47c41dfe5c50000000002000000000003660000c000000010000000148436e954690b7dbea7d900f78c9f4b0000000004800000a000000010000000484cebe57940ce15323e5b1b75e520f220000000373ab78f30293f8da29923a9eda47351355f2e3f2659ab55c9f61c2342e1c417140000007317556ac035038ac14c55031319b98b27ded63b" | convertto-securestring 
$ServicePrefix=$StackCode + $DC

if ($OverrideNamingRules=$true)
{
$NumberofServers=1
}


Switch ($DC)
{
"DC1" 
{
$VirtualNetworkName="TWS-VNET-WUS2-PROD"
$VirtualNetworkResourceGroup="Hypernet-WUS2-RG" 
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-WUS2-RG"
$DCCode="BY3"
}
"DC2" 
{ 
$VirtualNetworkName="TWS-VNET-EUS2-PROD"
$VirtualNetworkResourceGroup="Hypernet-EUS2-RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-EUS2-RG"
$DCCode="BN2"
}
"DC3" 
{ 
$VirtualNetworkName="TWS-VNET-NEUR-PROD"
$VirtualNetworkResourceGroup="Hypernet-NEUR-RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="TWS-VM-NEUR-RG"
$DCCode="DB5"
}
"POC" 
{ 
$VirtualNetworkName="TWSHYPERNET-WUS2-1"
$VirtualNetworkResourceGroup="HypernetWUS2RG"
$MachineSubnetName="Subnet1"
$VMResourceGroup="UST-TWS-PROD-RG"
$DCCode="MWH"
}

}


for ($ctr=1; $ctr -le $NumberofServers; $ctr++)
{
if ($OverrideNamingRules -eq $true)
{
$vmname=$ServerName
}
else
{
$vmname=$DCCode + "TWS" + $Role + $StackCode + $StartCounter
}
$StartCounter++
$DeploymentName=$vmname + "_Deployment"

Switch ($Role)
{
"SQL"
{
$templatepath=$sqlTemplate
New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -Disk3-H-Drive $HDrive -Disk4-O-Drive $ODrive -Disk5-T-Drive $TDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -AsJob
}
"Web"
{
$templatepath=$webTemplate
New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -AsJob
}
}

}

