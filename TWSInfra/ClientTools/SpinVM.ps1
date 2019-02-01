
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
$DC="DC2" 
$StackCode="WCB"
$StartCounter=101
$NumberofServers=8
$CDrive=256 
$DDrive=128
$EDrive=2048
$HDrive=2048
$ODrive=2048
$TDrive=256 
$SKU="Standard_DS12_v2" 
$StorageType="StandardSSD_LRS"
$DomainAccountName="phx\ajayvel"
$DomainPassword = Read-Host -Prompt "Enter your PHX DOMAIN Password" -AsSecureString



#DO NOT CHANGE THE BELOW VALUES. CONTACT RAJESHBS OR AJAYVEL FOR USING THE BELOW PARAMETERS.
$ServerName=""
$OverrideNamingRules=$false
#END OF PARAMETERS


#AUTOGENERATION 
$Domaintojoin="PHX.GBL"
$OUPath="OU=TWS-Services,OU=Resource,OU=Production,DC=phx,DC=gbl"
$LocalAdminName="twsadmin"
$LocalAdminSecuredPassword = ConvertTo-SecureString -AsPlainText "TWS@dm1n#007" -Force
$ServicePrefix=$StackCode + $DC

if ($OverrideNamingRules -eq $true)
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
    "Deploying the VM: $vmname"
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

