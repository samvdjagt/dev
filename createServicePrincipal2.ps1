#Initializing variables
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$AutomationAccountName = Get-AutomationVariable -Name 'AccountName'
$AppName = Get-AutomationVariable -Name 'AppName'

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
$CredentialAssetName = 'ManagementUXDeploy'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$AzCredentials = Get-AutomationPSCredential -Name $CredentialAssetName
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

# Get the Role Assignment of the authenticated user
$RoleAssignment = Get-AzRoleAssignment -SignInName $context.Account

# Validate whether the authenticated user having the Owner or Contributor role
if ($RoleAssignment.RoleDefinitionName -eq "Owner" -or $RoleAssignment.RoleDefinitionName -eq "Contributor")
{
	#$requiredAccessName=$ResourceURL.Split("/")[3]
	$redirectURL = "https://" + "$AppName" + ".azurewebsites.net" + "/"
	
	# Check whether the AD Application exist/ not
	$existingApplication = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue
	if ($existingApplication -ne $null)
	{
		$appId = $existingApplication.ApplicationId
		Write-Output "An AAD Application already exists with AppName $AppName(Application Id: $appId). Choose a different AppName" -Verbose
		exit
	}

	try
	{
		# Create a new AD Application with provided AppName
		$azAdApplication = New-AzureADApplication -DisplayName $AppName -PublicClient $false -AvailableToOtherTenants $false -ReplyUrls $redirectURL
	}
	catch
	{
		Write-Error "You must call the Connect-AzureAD cmdlet before calling any other cmdlets"
		exit
	}

	# Create a Client Secret
	$StartDate = Get-Date
	$EndDate = $StartDate.AddYears(280)
	$Guid = New-Guid
	$PasswordCredential = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordCredential
	$PasswordCredential.StartDate = $StartDate
	$PasswordCredential.EndDate = $EndDate
	$PasswordCredential.KeyId = $Guid
	$PasswordCredential.Value = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($Guid)))) + "="
	$ClientSecret = $PasswordCredential.Value

	Write-Output "Creating a new Application in AAD" -Verbose
	
	# Create an app credential to the Application
	$secureClientSecret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
	New-AzADAppCredential -ObjectId $azAdApplication.ObjectId -Password $secureClientSecret -StartDate $StartDate -EndDate $EndDate

	# Get the applicationId
	$applicationId = $azAdApplication.AppId
	Write-Output "Azure AAD Application creation completed successfully with AppName $AppName (Application Id is: $applicationId)" -Verbose

	# Create new Service Principal
	Write-Output "Creating a new Service Principal" -Verbose
	$ServicePrincipal = New-AzADServicePrincipal -ApplicationId $applicationId

	# Get the Service Principal
	Get-AzADServicePrincipal -ApplicationId $applicationId
	$ServicePrincipalName = $ServicePrincipal.ServicePrincipalNames
	Write-Output "Service Principal creation completed successfully for AppName $AppName (Application Id is: $applicationId)" -Verbose

	$ownerId = (Get-AzADUser -UserPrincipalName $username).Id
	Add-AzureADApplicationOwner -ObjectId $azAdApplication.ObjectId -RefObjectId $ownerId
	Write-Output "Azure admin successfully assigned owner role on the service principal" -Verbose

	#Collecting WVD Serviceprincipal Api Permission and set to client app registration
	$WVDServPrincipalApi = Get-AzADServicePrincipal -ApplicationId "5a0aa725-4958-4b0c-80a9-34562e23f3b7"
	$WVDServicePrincipal = Get-AzureADServicePrincipal -ObjectId $WVDServPrincipalApi.Id
	$AzureAdResouceAcessObject = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
	$AzureAdResouceAcessObject.ResourceAppId = $WVDServicePrincipal.AppId
	foreach ($permission in $WVDServicePrincipal.Oauth2Permissions) {
		$AzureAdResouceAcessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id,"Scope"
	}
	#Collecting AzureService Management Api permission and set to client app registration
	$AzureServMgmtApi = Get-AzADServicePrincipal -ApplicationId "797f4846-ba00-4fd7-ba43-dac1f8f63013"
	$AzureAdServMgmtApi = Get-AzureADServicePrincipal -ObjectId $AzureServMgmtApi.Id
	$AzureServMgmtApiResouceAcessObject = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
	$AzureServMgmtApiResouceAcessObject.ResourceAppId = $AzureAdServMgmtApi.AppId
	foreach ($SerVMgmtAPipermission in $AzureAdServMgmtApi.Oauth2Permissions) {
		$AzureServMgmtApiResouceAcessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $SerVMgmtAPipermission.Id,"Scope"
	}

	# Set Microsoft Graph API permission to Client App Registration
	$MsftGraphApi = Get-AzADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
	$AzureGraphApiPrincipal = Get-AzureADServicePrincipal -ObjectId $MsftGraphApi.Id
	$AzureGraphApiAccessObject = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
	$AzureGraphApiAccessObject.ResourceAppId = $AzureGraphApiPrincipal.AppId
	$permission = $AzureGraphApiPrincipal.Oauth2Permissions | Where-Object { $_.Value -eq "User.Read" }
	$AzureGraphApiAccessObject.ResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id,"Scope"
	$permission2 = $AzureGraphApiPrincipal.Oauth2Permissions | Where-Object { $_.Value -eq "User.ReadWrite" }
	$AzureGraphApiAccessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission2.Id,"Scope"
	$permission3 = $AzureGraphApiPrincipal.Oauth2Permissions | Where-Object { $_.Value -eq "Group.ReadWrite.all" }
	$AzureGraphApiAccessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission3.Id,"Scope"
	$permission4 = $AzureGraphApiPrincipal.AppRoles | Where-Object { $_.Value -eq "Application.ReadWrite.OwnedBy" }
	$AzureGraphApiAccessObject.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission4.Id,"Role"

	# Add the WVD API,Log Analytics API and Microsoft Graph API permissions to the ADApplication
	Set-AzureADApplication -ObjectId $azAdApplication.ObjectId -RequiredResourceAccess $AzureAdResouceAcessObject,$AzureServMgmtApiResouceAcessObject,$AzureGraphApiAccessObject -ErrorAction Stop
    #Set-AzureADApplication -ObjectId $azAdApplication.ObjectId -Oauth2Permissions $AzureAdOauth2Object -Oauth2RequirePostResponse $false -Oauth2AllowImplicitFlow $true
    
	$global:servicePrincipalCredentials = New-Object System.Management.Automation.PSCredential ($applicationId, $secureClientSecret)
	New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -Name "PrincipalId" -Encrypted $False -Value $applicationId -ResourceGroupName $ResourceGroupName
	New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -Name "Secret" -Encrypted $False -Value $secureClientSecret -ResourceGroupName $ResourceGroupName
	New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -Name "ObjectId" -Encrypted $False -Value $azAdApplication.ObjectId -ResourceGroupName $ResourceGroupName
	
	New-AzAutomationCredential -AutomationAccountName $AutomationAccountName -Name "ServicePrincipalCred" -Value $servicePrincipalCredentials -ResourceGroupName $ResourceGroupName
	
	# Get the Client Id/Application Id and Client Secret
	Write-Output "Credentials for the service principal are stored in the `$servicePrincipalCredentials object"
	New-AzRoleAssignment -RoleDefinitionName "Contributor" -ApplicationId $applicationId
	New-AzRoleAssignment -RoleDefinitionName "User Access Administrator" -ApplicationId $applicationId
}
else
{
	Write-Output "Authenticated user should have the Owner/Contributor permissions"
}
