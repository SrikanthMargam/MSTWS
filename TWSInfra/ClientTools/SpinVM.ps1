
#Template Location
$sqlTemplate = "https://raw.githubusercontent.com/MSTWS/TWSArm/phxdomain/TWSInfra/Templates/sql-vm-deploy.json"
$webTemplate = "https://raw.githubusercontent.com/MSTWS/TWSArm/phxdomain/TWSInfra/Templates/web-vm-deploy.json"
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
$Role = "WEB"
$SubRole = "WEB" 
$DC = "POC" 
$StackCode = "SRS"
$StartCounter = 101
$NumberofServers = 1
$CDrive = 256
$DDrive = 128
$EDrive = 512
$SKU = "Standard_DS12_v2" 
$StorageType = "StandardSSD_LRS"
$DomainAccountName = "phx\ajayvel"
$DomainPassword = Read-Host -Prompt "Enter your DOMAIN Password for $DomainAccountName" -AsSecureString



#MENTION ONLY IF SQL SERVERS ELSE IGNORE
$HDrive = 1024
$ODrive = 256
$TDrive = 256 

#DO NOT CHANGE THE BELOW VALUES. CONTACT RAJESHBS OR AJAYVEL FOR USING THE BELOW PARAMETERS.
$ServerName = "BN2TWSFILOCO101"
$OverrideNamingRules = $false
#END OF PARAMETERS


#AUTOGENERATION 
$Domaintojoin = "PHX.GBL"
$OUPath = "OU=TWS-Services,OU=Resource,OU=Production,DC=phx,DC=gbl"
$LocalAdminName = "twsadmin"
$LocalAdminSecuredPassword = ConvertTo-SecureString -AsPlainText "TWS@dm1n#007" -Force
$ServicePrefix = $StackCode + $DC

if ($OverrideNamingRules -eq $true) {
    $NumberofServers = 1
}

Switch ($DC) {
    "DC0" {
        #BAY DC
        $XpertTWSEnvName = "WindowsStore-Prod-WestUS2" #If Xpert Install these variable need to be paramterised.
        $xpertservicekey = "1EE9AE3EF56E8B56EB3E997894AE341B0922CC37D75A8762E6F36D1922EC51EFF6632B0AB59549B9839CF34351FB81CC32396D0987C0C3A78C306E12A71D3D61"

        $VirtualNetworkName = "TWS-VNET-WUS-PROD"
        $VirtualNetworkResourceGroup = "Hypernet-WUS-RG" 
        $MachineSubnetName = "Subnet1"
        $VMResourceGroup = "TWS-VM-WUS-RG"
        $DCCode = "BA3"

    }
    "DC1" {
        #West US2 DC
        $XpertTWSEnvName = "WindowsStore-Prod-WestUS2" #If Xpert Install these variable need to be paramterised.
        $xpertservicekey = "1EE9AE3EF56E8B56EB3E997894AE341B0922CC37D75A8762E6F36D1922EC51EFF6632B0AB59549B9839CF34351FB81CC32396D0987C0C3A78C306E12A71D3D61"

        $VirtualNetworkName = "TWS-VNET-WUS2-PROD"
        $VirtualNetworkResourceGroup = "Hypernet-WUS2-RG" 
        $MachineSubnetName = "Subnet1"
        $VMResourceGroup = "TWS-VM-WUS2-RG"
        $DCCode = "BY3"
    }
    "DC2" {

        #East US2 DC
        $XpertTWSEnvName = "WindowsStore-Prod-EastUS2"
        $xpertservicekey = "1B90F2CF04D7290AB8C7C34C8B521988CB1568659C9E9D57C925E354CE96906DC19DF07D09C828B01695EE6FCA4C07AD59EB6504B90345CA0F93276A0D903DD6"
 
        $VirtualNetworkName = "TWS-VNET-EUS2-PROD"
        $VirtualNetworkResourceGroup = "Hypernet-EUS2-RG"
        $MachineSubnetName = "Subnet1"
        $VMResourceGroup = "TWS-VM-EUS2-RG"
        $DCCode = "BN2"
    }

    "DC3" { 
        #North Euprope DC
        $XpertTWSEnvName = "WindowsStore-Prod-NorthEurope"
        $xpertservicekey = "B3BB776261E4B53997C2E7EF5B3154FB364C544A8640DEACB1C8A37F111E5D321344B989B879CD5EE448943306F50D60E1313EFDC14CC7347BC24AB344F94799"

        $VirtualNetworkName = "TWS-VNET-NEUR-PROD"
        $VirtualNetworkResourceGroup = "Hypernet-NEUR-RG"
        $MachineSubnetName = "Subnet1"
        $VMResourceGroup = "TWS-VM-NEUR-RG"
        $DCCode = "DB5"
    }
    "POC" { 
        #BAY DC
        $XpertTWSEnvName = "WindowsStore-Prod-WestUS2" #If Xpert Install these variable need to be paramterised.
        $xpertservicekey = "1EE9AE3EF56E8B56EB3E997894AE341B0922CC37D75A8762E6F36D1922EC51EFF6632B0AB59549B9839CF34351FB81CC32396D0987C0C3A78C306E12A71D3D61"

        $VirtualNetworkName = "TWSHYPERNET-WUS2-1"
        $VirtualNetworkResourceGroup = "HypernetWUS2RG"
        $MachineSubnetName = "Subnet1"
        $VMResourceGroup = "UST-TWS-PROD-RG"
        $DCCode = "MWH"
    }

}

Switch ($StackCode) {
    "WPW" {
        $XpertRoleName = "AntiPiracyStack"
    }
    "WDW" {
        $XpertRoleName = "AppCatalogReviewStack"
    }
    "BPB" {
        $XpertRoleName = "BackEndPipeline"
    }
    "WIW" {
        $XpertRoleName = "ClientInputStack"
    }
    "WTW" {
        $XpertRoleName = "ComTransactionLicenseStack"
    }
    "WAW" {
        $XpertRoleName = "ConfigStackPrimary"
    }
    "OCO" {
        $XpertRoleName = "ContentOrigin"
    }
    "WSW" {
        $XpertRoleName = "DataPresentationStack"
    }
    "WQW" {
        $XpertRoleName = "EventQueueStack"
    }
    "WCW" {
        $XpertRoleName = "IdentityCatalogConsumerStack"
    }

    "WLW" {
        $XpertRoleName = "LPS"
    }

    "WCW" {
        $XpertRoleName = "PipelineStack"
    }

    "DFP" {
        $XpertRoleName = "DevPortalFile"
    }

    "ACP" {
        $XpertRoleName = "PortalAppFabricCache"
    }

    "WPP" {
        $XpertRoleName = "PortalDetailsStack"
    }

    "PRP" {
        $XpertRoleName = "PortalFrontEndWeb"
    }


    "WSP" {
        $XpertRoleName = "PortalStack"
    }

    "SLR" {
        $XpertRoleName = "RemoteSigningFrontEndWeb"
    }

    "ACS" {
        $XpertRoleName = "ServicesAppFabricCache"
    }

    "AIS" {
        $XpertRoleName = "ServicesAppFabricCache"
    }

    "SMS" {
        $XpertRoleName = "ServicesFESQLPipelinePrincipal"
    }

    "SRS" {
        $XpertRoleName = "ServicesFrontEndWeb"
    }

    "PAT" {
        $XpertRoleName = "PatchingandTools"
    }

    "WAP" {
        $XpertRoleName = "PortalAuditStack"
    }

    "GFB" {
        $XpertRoleName = "GeneralPurposeStorage"
    }

    "UTL" {
        $XpertRoleName = "PatchingandTools"
    }

    default {
        $XpertRoleName = "UCProdServer"
    }

}

if ($DC -eq "POC") {
    $XpertRoleName = "POCMachines"
}

for ($ctr = 1; $ctr -le $NumberofServers; $ctr++) {
    if ($OverrideNamingRules -eq $true) {
        Write-Host "Print Hello"
        $vmname = $ServerName
    }
    else {
        $vmname = $DCCode + "TWS" + $SubRole + $StackCode + $StartCounter
    }
    $StartCounter++
    $DeploymentName = $vmname + "_Deployment"

    Write-Host "Parameters: -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -Disk3-H-Drive $HDrive -Disk4-O-Drive $ODrive -Disk5-T-Drive $TDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword  -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey -AsJob"

    Switch ($Role) {

        "SQL" {
            $templatepath = $sqlTemplate
            New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -Disk3-H-Drive $HDrive -Disk4-O-Drive $ODrive -Disk5-T-Drive $TDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey  -AsJob
        }
        "Web" {
            $templatepath = $webTemplate
            New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $VMResourceGroup -TemplateFile $templatepath -VMName $vmname -SizeofOSDiskInGB $CDrive -Disk1-D-Drive $DDrive -Disk2-E-Drive $EDrive -ManagedDiskStorageType $StorageType -VmSize $SKU -ServicePrefix $ServicePrefix -AdminUserName $LocalAdminName -AdminPassword $LocalAdminSecuredPassword -OUPath $OUPath -MachineSubnetName $MachineSubnetName -VirtualNetworkResourceGroup $VirtualNetworkResourceGroup -VirtualNetworkName $VirtualNetworkName -Domaintojoin $Domaintojoin  -DomainUsername $DomainAccountName -DomainPassword $DomainPassword -XpertEnvName $XpertTWSEnvName -XpertRole $XpertRoleName -XpertServiceKey $xpertservicekey -AsJob
        }
    }

}

