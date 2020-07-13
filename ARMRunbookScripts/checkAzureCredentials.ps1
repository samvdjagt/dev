param(
	[string] [Parameter(Mandatory=$true)] $username,
	[string] [Parameter(Mandatory=$true)] $password
)

Import-Module AzureAD

$ErrorActionPreference = 'Stop'

$Credential = New-Object System.Management.Automation.PsCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $Credential