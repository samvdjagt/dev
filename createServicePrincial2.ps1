#Initializing variables
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$RDBrokerURL = Get-AutomationVariable -Name 'RDBrokerURL'
$ResourceURL = Get-AutomationVariable -Name 'ResourceURL'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$AutomationAccountName = Get-AutomationVariable -Name 'accountName'
$WebApp = Get-AutomationVariable -Name 'webApp'
$ApiApp = Get-AutomationVariable -Name 'apiApp'

$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
if($Filename -eq "AzureModules.zip"){
Invoke-WebRequest -Uri $fileURI/scripts/$Filename -OutFile "C:\$Filename"
}else{
Invoke-WebRequest -Uri $fileURI/$Filename -OutFile "C:\$Filename"
}
}
#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Websites -Global
Import-Module Az.Automation -Global
Import-Module AzureAD -Global

Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false
Get-ExecutionPolicy -List
#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$CredentialAssetName = 'ManagementUXDeploy'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$AzCredentials = Get-AutomationPSCredential -Name $CredentialAssetName
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Select-AzSubscription -SubscriptionId $SubscriptionId

New-Item -Path "C:\msft-wvd-saas-web" -ItemType directory -Force -ErrorAction SilentlyContinue
$WebAppDirectory = "C:\msft-wvd-saas-web"

#Function to get PublishingProfileCredentials
function Get-PublishingProfileCredentials ($resourceGroupName,$webAppName) {

	$resourceType = "Microsoft.Web/sites/config"
	$resourceName = "$webAppName/publishingcredentials"

	$publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $resourceGroupName -ResourceType $resourceType -ResourceName $resourceName -Action list -ApiVersion 2015-08-01 -Force

	return $publishingCredentials
}

#Function to get KuduApiAuthorisationHeaderValue
function Get-KuduApiAuthorisationHeaderValue ($resourceGroupName,$webAppName,$slotName = $null) {
	$publishingCredentials = Get-PublishingProfileCredentials $resourceGroupName $webAppName $slotName
	return ("Basic {0}" -f [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $publishingCredentials.Properties.PublishingUserName,$publishingCredentials.Properties.PublishingPassword))))
}

#Function to confirm files are uploaded or not in both azure app services
function RunCommand ($dir,$command,$resourceGroupName,$webAppName,$slotName = $null) {
	$kuduApiAuthorisationToken = Get-KuduApiAuthorisationHeaderValue $resourceGroupName $webAppName $slotName
	$kuduApiUrl = "https://$webAppName.scm.azurewebsites.net/api/command"
	$Body =
	@{
		"command" = $command;
		"dir" = $dir
	}
	$bodyContent = @($Body) | ConvertTo-Json
	#Write-output $bodyContent
	Invoke-RestMethod -Uri $kuduApiUrl `
 		-Headers @{ "Authorization" = $kuduApiAuthorisationToken; "If-Match" = "*" } `
 		-Method POST -ContentType "application/json" -Body $bodyContent
}

try
{
	# Get Url of Web-App
	$GetWebApp = Get-AzWebApp -Name $WebApp -ResourceGroupName $ResourceGroupName
	$WebUrl = $GetWebApp.DefaultHostName

	#$requiredAccessName=$ResourceURL.Split("/")[3]
	$redirectURL = "https://" + "$WebUrl" + "/"

    #Get the credential with the above name from the Automation Asset store
    $Credentials = Get-AutomationPSCredential -Name $CredentialAssetName
    #Connect to AzureAD
    Connect-AzureAD -Credential $Credentials

	#Static value of wvdInfra web appname/appid
	$wvdinfraWebAppId = "5a0aa725-4958-4b0c-80a9-34562e23f3b7"
	$serviceIdinfo = Get-AzADServicePrincipal -ErrorAction SilentlyContinue | Where-Object { $_.ApplicationId -eq $wvdinfraWebAppId }

	$wvdInfraWebAppObjId = $serviceIdinfo.Id
	#generate unique ID based on subscription ID
	$unique_subscription_id = ($SubscriptionId).Replace('-','').substring(0,19)


	#generate the display name for native app in AAD
	$wvdSaaS_clientapp_display_name = "wvdSaaS" + $ResourceGroupName.ToLowerInvariant() + $unique_subscription_id.ToLowerInvariant()
	
	#Creating ClientApp Ad application in azure Active Directory
	$clientAdApp = New-AzureADApplication -DisplayName $wvdSaaS_clientapp_display_name -ReplyUrls $redirectURL -PublicClient $true -AvailableToOtherTenants $false -Verbose -ErrorAction Stop

	#Collecting WVD Serviceprincipal Api Permission
	$WVDServicePrincipal = Get-AzureADServicePrincipal -ObjectId $wvdInfraWebAppObjId #-SearchString $wvdInfraWebAppName | Where-Object {$_.DisplayName -eq $wvdInfraWebAppName}
    
	$AzureAdResouceAcessObject = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
	$AzureAdResouceAcessObject.ResourceAppId = $WVDServicePrincipal.AppId
	foreach ($permission in $WVDServicePrincipal.Oauth2Permissions) {
		$AzureAdResouceAcessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id,"Scope"
	}

	#Collecting AzureService Management Api permission
	$AzureServMgmtApi = Get-AzADServicePrincipal -ApplicationId "797f4846-ba00-4fd7-ba43-dac1f8f63013"
	$AzureAdServMgmtApi = Get-AzureADServicePrincipal -ObjectId $AzureServMgmtApi.Id
	$AzureServMgmtApiResouceAcessObject = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
	$AzureServMgmtApiResouceAcessObject.ResourceAppId = $AzureAdServMgmtApi.AppId
	foreach ($SerVMgmtAPipermission in $AzureAdServMgmtApi.Oauth2Permissions) {
		$AzureServMgmtApiResouceAcessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $SerVMgmtAPipermission.Id,"Scope"
	}

	#Adding WVD Api Required Access and Azure Service Management Api required access Permissions to ClientAPP AD Application.
	Set-AzureADApplication -ObjectId $clientAdApp.ObjectId -RequiredResourceAccess $AzureAdResouceAcessObject,$AzureServMgmtApiResouceAcessObject -ErrorAction Stop
	
}

catch
{
	Write-Output $_.Exception.Message
	throw $_.Exception.Message
}

New-PSDrive -Name RemoveAccount -PSProvider FileSystem -Root "C:\" | Out-Null
@"
Param(
    [Parameter(Mandatory=`$True)]
    [string] `$SubscriptionId,
    [Parameter(Mandatory=`$True)]
    [string] `$ResourceGroupName,
    [Parameter(Mandatory=`$True)]
    [string] `$AutomationAccountName,
    [Parameter(Mandatory=`$True)]
    [string] `$fileURI
 
)
Invoke-WebRequest -Uri `$fileURI/scripts/AzureModules.zip -OutFile "C:\AzureModules.zip"
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue
Import-Module Az.profile
Import-Module Az.Automation
Import-Module Az.Resources
#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
`$CredentialAssetName = 'ManagementUXDeploy'
#Get the credential with the above name from the Automation Asset store
`$Credentials = Get-AutomationPSCredential -Name `$CredentialAssetName
Add-AzAccount -Environment "AzureCloud" -Credential `$Credentials
Select-AzSubscription -SubscriptionId `$SubscriptionId
`$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName `$ResourceGroupName -Name `$AutomationAccountName
if(`$AutomationAccount){
#Remove-AzAutomationAccount -Name `$AutomationAccountName -ResourceGroupName `$ResourceGroupName -Force
`$resourcedetails = Get-AzResource -Name `$AutomationAccountName -ResourceGroupName `$ResourceGroupName
Remove-AzResource -ResourceId `$resourcedetails.ResourceId -Force
}else{
exit
}
"@ | Out-File -FilePath RemoveAccount:\RemoveAccount.ps1 -Force

$runbookName = 'removewvdsaasacctbook'
#Create a Run Book
New-AzAutomationRunbook -Name $runbookName -Type PowerShell -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName

#Import modules to Automation Account
$modules = "Az.profile,Az.compute,Az.resources"
$modulenames = $modules.Split(",")
foreach ($modulename in $modulenames) {
	Set-AzAutomationModule -Name $modulename -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourcegroupName
}

#Importe powershell file to Runbooks
Import-AzAutomationRunbook -Path "C:\RemoveAccount.ps1" -Name $runbookName -Type PowerShell -ResourceGroupName $ResourcegroupName -AutomationAccountName $AutomationAccountName -Force

#Publishing Runbook
Publish-AzAutomationRunbook -Name $runbookName -ResourceGroupName $ResourcegroupName -AutomationAccountName $AutomationAccountName

#Providing parameter values to powershell script file
$params = @{ "ResourcegroupName" = $ResourcegroupName; "SubscriptionId" = $SubscriptionId; "AutomationAccountName" = $AutomationAccountName; "fileURI" = $fileURI }
Start-AzAutomationRunbook -Name $runbookName -ResourceGroupName $ResourcegroupName -AutomationAccountName $AutomationAccountName -Parameters $params | Out-Null
