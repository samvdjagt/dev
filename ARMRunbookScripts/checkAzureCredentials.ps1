param(
	[string] [Parameter(Mandatory=$true)] $username,
	[System.Security.SecureString] [Parameter(Mandatory=$true)] $password
)

$ErrorActionPreference = 'Stop'

$Credential = New-Object System.Management.Automation.PsCredential($username, $password)
Connect-AzAccount -credential $Credential