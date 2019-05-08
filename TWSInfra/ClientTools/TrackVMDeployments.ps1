$VMNameTobeTracked="BY3TWSSQLWTW104,BY3TWSSQLWTW105,BY3TWSSQLWTW106,BY3TWSSQLWTW107,BY3TWSSQLWTW108,BY3TWSSQLWTW109,BY3TWSSQLWTW110,BY3TWSSQLWTW111,BY3TWSSQLWTW112,BY3TWSSQLWTW113,BY3TWSSQLWTW114"
$VMNameTobeTracked=$VMNameTobeTracked.Split(",")
$RunningFlag=$true
While ($RunningFlag)
{

$AllDeployments=""
$AllDeployments=Get-AzureRmResourceGroupDeployment -ResourceGroupName "TWS-VM-WUS2-RG" |  where-object {$VMNameTobeTracked -contains $_.DeploymentName.Replace("_Deployment","")}
$AllDeployments+=Get-AzureRmResourceGroupDeployment -ResourceGroupName 'TWS-VM-EUS2-RG' | where-object {$VMNameTobeTracked -contains $_.DeploymentName.Replace("_Deployment","")}
$AllDeployments+=Get-AzureRmResourceGroupDeployment -ResourceGroupName 'TWS-VM-NEUR-RG' | where-object {$VMNameTobeTracked -contains $_.DeploymentName.Replace("_Deployment","")}
$AllDeployments+=Get-AzureRmResourceGroupDeployment -ResourceGroupName 'UST-TWS-PROD-RG' | where-object {$VMNameTobeTracked -contains $_.DeploymentName.Replace("_Deployment","")}
Clear-Host
$AllDeployments | Select DeploymentName, ResourceGroupName, ProvisioningState, TimeStamp, Mode | Sort TimeStamp | Format-Table

$RunningDeployments=$AllDeployments | where provisioningstate -eq "Running" | measure
if ($RunningDeployments.Count -eq 0)
{$RunningFlag=$false
}
else
{
Write-Host "There are Deployments still in Running State... Sleeping for 10 Seconds and continue to poll the status once again..."
Sleep 10
}

}







