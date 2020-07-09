﻿#Initializing variables from automation account
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$AutomationAccountName = Get-AutomationVariable -Name 'AccountName'
$AppName = Get-AutomationVariable -Name 'AppName'
$principalId = Get-AutomationVariable -Name 'principalId'
$orgName = Get-AutomationVariable -Name 'orgName'
$projectName = Get-AutomationVariable -Name 'projectName'
$location = Get-AutomationVariable -Name 'location'
$adminUsername = Get-AutomationVariable -Name 'adminUsername'
$domainName = Get-AutomationVariable -Name 'domainName'
$keyvaultName = Get-AutomationVariable -Name 'keyvaultName'
$wvdAssetsStorage = Get-AutomationVariable -Name 'assetsName'
$profilesStorageAccountName = Get-AutomationVariable -Name 'profilesName'
$ObjectId = Get-AutomationVariable -Name 'ObjectId'
$tenantAdminDomainJoinUPN = Get-AutomationVariable -Name 'tenantAdminDomainJoinUPN'
$existingSubnetName = Get-AutomationVariable -Name 'existingSubnetName'
$virtualNetworkResourceGroupName = Get-AutomationVariable -Name 'virtualNetworkResourceGroupName'
$existingVnetName = Get-AutomationVariable -Name 'existingVnetName'
$computerName = Get-AutomationVariable -Name 'computerName'

# Download files required for this script from github ARMRunbookScripts/static folder
$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"
}

#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

# Install required Az modules and AzureAD
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Websites -Global
Import-Module Az.Automation -Global
Import-Module Az.Managedserviceidentity -Global
Import-Module Az.Keyvault -Global
Import-Module AzureAD -Global

Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false
Get-ExecutionPolicy -List

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$CredentialAssetName = 'ServicePrincipalCred'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$SPCredentials = Get-AutomationPSCredential -Name $CredentialAssetName

$CredentialAssetName3 = Get-AutomationPSCredential -Name "domainJoinCredentials"

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

# Get token for web request authorization
$tenant = (Get-AzTenant).TenantId
$azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
$pat = $profileClient.AcquireAccessToken($context.Subscription.TenantId).AccessToken
$headers = @{    Authorization="Bearer $pat"}

$token = $pat
$token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))

#Create devops project
$url= $("https://dev.azure.com/" + $orgName + "/_apis/projects?api-version=5.1")
write-output $url

$body = @"
{
  "name": "$($projectName)",
  "description": "WVD Quickstart",
  "capabilities": {
    "versioncontrol": {
      "sourceControlType": "Git"
    },
    "processTemplate": {
      "templateTypeId": "6b724908-ef14-45cf-84f8-768b5384da45"
    }
  }
}
"@
write-output $body 

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Post -Body $Body -ContentType application/json
write-output $response

start-sleep -Seconds 5  # to make sure project creation completed - would sometimes fail next request without this. TODO: more robust solution here

# Create the service connection between devops and Azure using the service principal created in the createServicePrincipal script
$url= $("https://dev.azure.com/" + $orgName + "/" + $projectName + "/_apis/serviceendpoint/endpoints?api-version=5.1-preview.2")
write-output $url
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SPCredentials.Password)
$key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$subscriptionName = (Get-AzContext).Subscription.Name
$body = @"
{
  "authorization": {
    "parameters": {
      "tenantid": "$($tenant)",
      "serviceprincipalid": "$($principalId)",
      "authenticationType": "spnKey",
      "serviceprincipalkey": "$($key)"
    },
    "scheme": "ServicePrincipal"
  },
  "data": {
    "subscriptionId": "$($SubscriptionId)",
    "subscriptionName": "$($subscriptionName)",
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
write-output $response
$endpointId = $response.id  # needed to set permissions later

# Get project ID to create repo. Not necessary if using default repo
$url = $("https://dev.azure.com/" + $orgName + "/_apis/projects/" + $projectName + "?api-version=5.1")
$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Get
$projectId = $response.id

# Create repo
$url= $("https://dev.azure.com/" + $orgName + "/_apis/git/repositories?api-version=5.1")
write-output $url

$body = @"
{
  "name": "$($projectName)",
  "project": {
    "id": "$($projectId)"
  }
}
"@
write-output $body 

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Post -Body $Body -ContentType application/json
write-output $response

# Clone public github repo with all the required files
$url= $("https://dev.azure.com/" + $orgName + "/" + $projectName + "/_apis/git/repositories/" + $projectName + "/importRequests?api-version=5.1-preview.1")
write-output $url 

$body = @"
{
  "parameters": {
    "gitSource": {
      "url": "https://github.com/samvdjagt/dev.git"
    }
  }
}
"@
write-output $body 

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Post -Body $Body -ContentType application/json
write-output $response

$split = $tenantAdminDomainJoinUPN.Split("@")
$domainUsername = $split[0]
$domainName = $split[1]

# Create test user for the new WVD environment
$credential = New-Object System.Management.Automation.PsCredential($domainName + "\" + $domainUsername, $CredentialAssetName3.password)
$Session = new-PSSession -ComputerName $computerName -Credential $credential
Invoke-Command -Session $Session  { Import-Module activedirectory }
Invoke-Command -Session $Session  { New-ADGroup -Name "WVDTestUsers" -SamAccountName WVDTestUsers -GroupCategory Security -GroupScope Global -DisplayName "WVD Test users" }
Invoke-Command -Session $Session  { New-ADUser -Name "WVDTestUser" -Enabled $True -SamAccountName "WVDTestUser" -AccountPassword $CredentialAssetName3.password -UserPrincipalName "WVDTestUser@$domainName" }
Invoke-Command -Session $Session  { Add-ADGroupMember -Identity "WVDTestUsers" -Members "WVDTestUser" }

Invoke-Command -Session $Session  { Import-Module ADSync }
Invoke-Command -Session $Session  { Start-ADSyncSyncCycle -PolicyType Delta -Verbose }

start-sleep -Seconds 60  # to make sure user was created. TODO: more robus solution to achieve this

$principalIds = (Invoke-Command -Session $Session  { (Get-ADGroup -Name "WVDTestUsers").objectId } )

# Get ID of the commit we just pushed, needed for the next commit below
$url = $("https://dev.azure.com/" + $orgName + "/" + $projectName + "/_apis/git/repositories/" + $projectName + "/refs?filter=heads/master&api-version=5.1")
write-output $url

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Get
write-output $response

# Parse user input into the template variables file and the deployment parameter file and commit them to the devops repo
$url = $("https://dev.azure.com/" + $orgName + "/" + $projectName + "/_apis/git/repositories/" + $projectName + "/pushes?api-version=5.1")
write-output $url

$downloadUrl = $($fileUri + "/QS-WVD/variables.template.yml")
$content = (New-Object System.Net.WebClient).DownloadString($downloadUrl)

$content = $content.Replace("[location]", $location)
$content = $content.Replace("[adminUsername]", $adminUsername)
$content = $content.Replace("[domainName]", $domainName)
$content = $content.Replace("[keyVaultName]", $keyvaultName)
$content = $content.Replace("[wvdAssetsStorage]", $wvdAssetsStorage)
$content = $content.Replace("[resourceGroupName]", $ResourceGroupName)
$content = $content.Replace("[profilesStorageAccountName]", $profilesStorageAccountName)
$content = $content.Replace('"', '')
write-output $content

$downloadUrl = $($fileUri + "/QS-WVD/static/appliedParameters.template.psd1")
$parameters = (New-Object System.Net.WebClient).DownloadString($downloadUrl)

# $parameters = $parameters.Replace("[principalIds]", $location)
$parameters = $parameters.Replace("[existingSubnetName]", $existingSubnetName)
$parameters = $parameters.Replace("[virtualNetworkResourceGroupName]", $virtualNetworkResourceGroupName)
$parameters = $parameters.Replace("[existingVnetName]", $existingVnetName)
$parameters = $parameters.Replace("[computerName]", $computerName)
$parameters = $parameters.Replace("[existingDomainUsername]", $domainUsername)
$parameters = $parameters.Replace("[existingDomainName]", $domainName)
$parameters = $parameters.Replace("[tenantAdminDomainJoinUPN]", $tenantAdminDomainJoinUPN)
$parameters = $parameters.Replace("[objectId]", $ObjectId)
$parameters = $parameters.Replace("[tenantId]", $tenant)
$parameters = $parameters.Replace("[subscriptionId]", $subscriptionId)
$parameters = $parameters.Replace("[location]", $location)
$parameters = $parameters.Replace("[adminUsername]", $adminUsername)
$parameters = $parameters.Replace("[domainName]", $domainName)
$parameters = $parameters.Replace("[keyVaultName]", $keyvaultName)
$parameters = $parameters.Replace("[assetsName]", $wvdAssetsStorage)
$parameters = $parameters.Replace("[profilesName]", $profilesStorageAccountName)
$parameters = $parameters.Replace("[resourceGroupName]", $ResourceGroupName)
$parameters = $parameters.Replace("[principalIds]", $principalIds)
$parameters = $parameters.Replace('"', "'")
write-output $parameters

$body = @"
{
  "refUpdates": [
    {
      "name": "refs/heads/master",
      "oldObjectId": "$($response.value.objectId)"
    }
  ],
  "commits": [
    {
      "comment": "Initial commit.",
      "changes": [
        {
          "changeType": "add",
          "item": {
            "path": "QS-WVD/variables.yml"
          },
          "newContent": {
            "content": "$($content)",
            "contentType": "rawtext"
          }
        },
	{
	  "changeType": "add",
          "item": {
            "path": "QS-WVD/static/appliedParameters.psd1"
          },
          "newContent": {
            "content": "$($parameters)",
            "contentType": "rawtext"
          }
        }
      ]
    }
  ]
}
"@
write-output $body

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization = "Basic $token"} -Method Post -Body $Body -ContentType application/json
write-output $response

# Give service principal access to the keyvault
Set-AzKeyVaultAccessPolicy -VaultName $keyvaultName -ServicePrincipalName $principalId -PermissionsToSecrets Get,Set,List,Delete,Recover,Backup,Restore

# Give pipeline permission to access the newly created service connection
$url = $("https://dev.azure.com/" + $orgName + "/" + $projectName + "/_apis/pipelines/pipelinePermissions/endpoint/" + $endpointId + "?api-version=5.1-preview.1")
write-output $url

$body = @"
{
    "allPipelines": {
        "authorized": true,
        "authorizedBy": null,
        "authorizedOn": null
    },
    "pipelines": null,
    "resource": {
        "id": "$($endpointId)",
        "type": "endpoint"
    }
}
"@
write-output $body

$response = Invoke-RestMethod -Method PATCH -Uri $url -Headers @{Authorization = "Basic $token"} -Body $body -ContentType "application/json"
write-output $response


