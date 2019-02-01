$VMNameTobeTracked="BY3TWSSQLWCB101,BY3TWSSQLWCB102,BY3TWSSQLWCB103,BY3TWSSQLWCB104,BY3TWSSQLWCB105,BY3TWSSQLWCB106,BY3TWSSQLWCB107,BY3TWSSQLWCB108"
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







