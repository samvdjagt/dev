param(    
    [Parameter(Mandatory = $true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string] $StorageAccountName,

    [Parameter(Mandatory = $true)]
    [string] $AzureAdminUPN,

    [Parameter(Mandatory = $true)]
    [string] $AzureAdminPassword

)

$Credential = New-Object System.Management.Automation.PsCredential($AzureAdminUPN, (ConvertTo-SecureString $AzureAdminPassword -AsPlainText -Force))
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Set-Location  C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.9\Downloads\8\_deploy\001-002-AzFiles
.\CopyToPSPath.ps1
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PowershellGet -MinimumVersion 2.2.4.1 -Force

Install-Module -Name Az -Force -Verbose

Import-Module -Name AzFilesHybrid -Force -Verbose
Connect-AzAccount -Credential $Credential
Select-AzSubscription -SubscriptionId $SubscriptionId
Join-AzStorageAccountForAuth -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -DomainAccountType 'ComputerAccount' -OrganizationalUnitName 'Domain Controllers' -OverwriteExistingADObject