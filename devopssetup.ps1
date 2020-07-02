﻿    #Initializing variables
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$AutomationAccountName = Get-AutomationVariable -Name 'AccountName'
$AppName = Get-AutomationVariable -Name 'AppName'
$principalId = Get-AutomationVariable -Name 'principalId'
$principalKey = Get-AutomationVariable -Name 'secret'


$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri $fileURI/$Filename -OutFile "C:\$Filename"
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
$CredentialAssetName = 'ServicePrincipalCred'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$PSCredentials = Get-AutomationPSCredential -Name $CredentialAssetName


#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$CredentialAssetName2 = 'ManagementUXDeploy'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$AzCredentials = Get-AutomationPSCredential -Name $CredentialAssetName2
$AzCredentials.password.MakeReadOnly()
$username = $AzCredentials.username
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $AzCredentials
Select-AzSubscription -SubscriptionId $SubscriptionId

# Get the context
$context = Get-AzContext
if ($context -eq $null)
{
	Write-Error "Please authenticate to Azure & Azure AD using Login-AzAccount and Connect-AzureAD cmdlets and then run this script"
	exit
}

    
$tenant = (Get-AzTenant).TenantId
$azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
$pat = $profileClient.AcquireAccessToken($context.Subscription.TenantId).AccessToken
$headers = @{    Authorization="Bearer $pat"}

$token = $pat

$url="https://dev.azure.com/{org name}/{project name}/_apis/serviceendpoint/endpoints?api-version=5.1-preview.2"
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PSCredentials.Password)
$key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)


$token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
$subscriptionName = (Get-AzContext).Subscription.Name
$body = @"
{
  "authorization": {
    "parameters": {
      "tenantid": $tenant,
      "serviceprincipalid": $principalId,
      "authenticationType": "spnKey",
      "serviceprincipalkey": $key
    },
    "scheme": "ServicePrincipal"
  },
  "data": {
    "subscriptionId": $subscriptionId,
    "subscriptionName": $subscriptionName,
    "environment": "AzureCloud",
    "scopeLevel": "Subscription"
  },
  "name": "WVDServiceConnection",
  "type": "azurerm",
  "url": "https://management.azure.com/"
}
"@

write-output $body 

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Post -Body $Body -ContentType application/json