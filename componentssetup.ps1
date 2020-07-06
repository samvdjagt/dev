<#
.SYNOPSIS
Run the Post-Deployment for the storage account deployment

.DESCRIPTION
Run the Post-Deployment for the storage account deployment
- Upload required data to the storage account

.PARAMETER orchestrationFunctionsPath
Mandatory. Path to the required functions

.PARAMETER storageAccountName
Mandatory. Name of the storage account to host the deployment files

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
Invoke-StorageAccountPostDeployment -orchestrationFunctionsPath $currentDir -storageAccountName "wvdStorageAccount"

Upload any required data to the storage account
#>

    #Initializing variables
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$AutomationAccountName = Get-AutomationVariable -Name 'AccountName'
$AppName = Get-AutomationVariable -Name 'AppName'
$principalId = Get-AutomationVariable -Name 'principalId'
$orgName = Get-AutomationVariable -Name 'orgName'
$projectName = Get-AutomationVariable -Name 'projectName'
$storageAccountName = Get-AutomationVariable -Name 'componentsStorage'


$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip,modules.zip"
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
$token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))



        Write-Verbose ("[{0} entered]" -f $MyInvocation.MyCommand)
        . "$orchestrationFunctionsPath\Storage\Import-WVDSoftware.ps1"
        . "$orchestrationFunctionsPath\Storage\Compress-WVDCSEContent.ps1"
        . "$orchestrationFunctionsPath\Storage\Export-WVDCSEContentToBlob.ps1"




        Write-Verbose "###############################"
        Write-Verbose "## Upload to storage account ##"
        Write-Verbose "###############################"

        $InputObject = @{
            ResourceGroupName  = (Get-AzResource -Name $storageAccountName -ResourceType 'Microsoft.Storage/storageAccounts').ResourceGroupName
            StorageAccountName = $storageAccountName
        }
        if ($PSCmdlet.ShouldProcess("Required storage content for storage account '$storageAccountName'", "Export")) {
            Export-WVDCSEContentToBlob @InputObject -Verbose
            Write-Verbose "Storage account content upload invocation finished"
        }

function Export-WVDCSEContentToBlob {

    [CmdletBinding(SupportsShouldProcess = $True)]
    param(
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Map of source/target tuples for upload"
        )]
        [Hashtable[]] $contentToUpload = $(
            @{
                sourcePath = 'C:\Pipeline\'
                targetBlob = 'components'
            }
        )
    )

    Write-Verbose "Getting storage account context."
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
    $ctx = $storageAccount.Context

    Write-Verbose "Building paths to the local folders to upload."
    Write-Verbose "Script Directory: '$PSScriptRoot'"
    $sourcesPath = Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) -Parent) -Parent) -Parent
    $contentDirectory = Join-Path -Path $sourcesPath "parameters/s/Implementation/2020-Spring/OrchestrationSources/Uploads"
    Write-Verbose "Content directory: '$contentDirectory'"

    foreach ($contentObject in $contentToUpload) {

        $sourcePath = $contentObject.sourcePath
        $targetBlob = $contentObject.targetBlob

        try {
            $pathToContentToUpload = $sourcePath
            Write-Verbose "Processing content in path: '$pathToContentToUpload'"
    
            Write-Verbose "Testing local path"
            If (-Not (Test-Path -Path $pathToContentToUpload)) {
                throw "Testing local paths FAILED: Cannot find content path to upload '$pathToContentToUpload'"
            }
            Write-Verbose "Testing paths: SUCCEEDED"
    
            Write-Verbose "Getting files to be uploaded..."
            $scriptsToUpload = Get-ChildItem -Path $pathToContentToUpload -ErrorAction Stop
            Write-Verbose "Files to be uploaded:"
            Write-Verbose ($scriptsToUpload.Name | Format-List | Out-String)

            Write-Verbose "Testing blob container"
            Get-AzStorageContainer -Name $targetBlob -Context $ctx -ErrorAction Stop
            Write-Verbose "Testing blob container SUCCEEDED"
    
            if ($PSCmdlet.ShouldProcess("Files to the '$targetBlob' container", "Upload")) {
                $scriptsToUpload | Set-AzStorageBlobContent -Container $targetBlob -Context $ctx -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Upload FAILED: $_"
        }
    }
}

