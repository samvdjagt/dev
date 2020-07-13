param(
	[string] [Parameter(Mandatory=$true)] $username,
	[string] [Parameter(Mandatory=$true)] $password
)

$ErrorActionPreference = 'Stop'

$Credential = New-Object System.Management.Automation.PsCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
Connect-AzAccount -credential $Credential