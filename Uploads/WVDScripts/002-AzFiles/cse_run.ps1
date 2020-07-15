[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # [Parameter(Mandatory = $true)]
    # [ValidateNotNullOrEmpty()]
    # [string] $storageAccountKey,

    [Parameter(Mandatory = $false)]
    [Hashtable] $DynParameters,

    [Parameter(Mandatory = $true)]
    [string] $AzureAdminUpn,

    [Parameter(Mandatory = $true)]
    [string] $AzureAdminPassword,

    [Parameter(Mandatory = $true)]
    [string] $domainJoinPassword,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigurationFileName = "azfiles.parameters.json"
)

#####################################

##########
# Helper #
##########
#region Functions
function LogInfo($message) {
    Log "Info" $message
}

function LogError($message) {
    Log "Error" $message
}

function LogSkip($message) {
    Log "Skip" $message
}

function LogWarning($message) {
    Log "Warning" $message
}

function Log {

    <#
    .SYNOPSIS
   Creates a log file and stores logs based on categories with tab seperation

    .PARAMETER category
    Category to put into the trace

    .PARAMETER message
    Message to be loged

    .EXAMPLE
    Log 'Info' 'Message'

    #>

    Param (
        $category = 'Info',
        [Parameter(Mandatory = $true)]
        $message
    )

    $date = get-date
    $content = "[$date]`t$category`t`t$message`n"
    Write-Verbose "$content" -verbose

    if (! $script:Log) {
        $File = Join-Path $env:TEMP "log.log"
        Write-Error "Log file not found, create new $File"
        $script:Log = $File
    }
    else {
        $File = $script:Log
    }
    Add-Content $File $content -ErrorAction Stop
}

function Set-Logger {
    <#
    .SYNOPSIS
    Sets default log file and stores in a script accessible variable $script:Log
    Log File name "executionCustomScriptExtension_$date.log"

    .PARAMETER Path
    Path to the log file

    .EXAMPLE
    Set-Logger
    Create a logger in
    #>

    Param (
        [Parameter(Mandatory = $true)]
        $Path
    )

    # Create central log file with given date

    $date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"

    $scriptName = (Get-Item $PSCommandPath ).Basename
    $scriptName = $scriptName -replace "-", ""

    Set-Variable logFile -Scope Script
    $script:logFile = "executionCustomScriptExtension_" + $scriptName + "_" + $date + ".log"

    if ((Test-Path $path ) -eq $false) {
        $null = New-Item -Path $path -type directory
    }

    $script:Log = Join-Path $path $logfile

    Add-Content $script:Log "Date`t`t`tCategory`t`tDetails"
}
#endregion


## MAIN
#Set-Logger "C:\WindowsAzure\CustomScriptExtension\Log" # inside "executionCustomScriptExtension_$date.log"
Set-Logger "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\executionLog\azfilesconfig" # inside "executionCustomScriptExtension_$scriptName_$date.log"

LogInfo("###################")
LogInfo("## 0 - LOAD DATA ##")
LogInfo("###################")
#$storageaccountkey = $DynParameters.storageaccountkey

$PsParam = Get-ChildItem -path "_deploy" -Filter $ConfigurationFileName -Recurse | sort -Property FullName
$ConfigurationFilePath=$PsParam.FullName
#$ConfigurationFilePath= Join-Path $PSScriptRoot $ConfigurationFileName

$ConfigurationJson = Get-Content -Path $ConfigurationFilePath -Raw -ErrorAction 'Stop'

try { $azfilesconfig = $ConfigurationJson | ConvertFrom-Json -ErrorAction 'Stop' }
catch {
    Write-Error "Configuration JSON content could not be converted to a PowerShell object" -ErrorAction 'Stop'
}

LogInfo("##################")
LogInfo("## 0 - EVALUATE ##")
LogInfo("##################")
foreach ($config in $azfilesconfig.azfilesconfig) {
    
    if ($config.enableAzureFiles) {
        LogInfo("############################")
        LogInfo("## 1 - Enable Azure Files ##")
        LogInfo("############################")
        LogInfo("Trigger user group creation")

        LogInfo("Set execution policy...")
        
        #Change the execution policy to unblock importing AzFilesHybrid.psm1 module
        Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

        #cd $PSScriptRoot
        #LogInfo("Current working directory: $PSScriptRoot")
        # Navigate to where AzFilesHybrid is unzipped and stored and run to copy the files into your path
        #.\CopyToPSPath.ps1 

        #LogInfo("Install Az...")
        #Install-Module -Name Az -Force

        #LogInfo("Import AzFilesHybrid module...")
        #Import-Module -Name AzFilesHybrid -Force

        #LogInfo("Login with an Azure AD credential with $username and $password")
        #$Credential = New-Object System.Management.Automation.PsCredential("admin@gt1027.onmicrosoft.com", (ConvertTo-SecureString "ReverseParol44" -AsPlainText -Force))
        #Connect-AzAccount -Credential $Credential

        #Define parameters
        $SubscriptionId = $config.SubscriptionId
        $SubscriptionId = $SubscriptionId.replace('"', "'")
        $ResourceGroupName = $config.ResourceGroupName
        $ResourceGroupName = $ResourceGroupName.replace('"', "'")
        $StorageAccountName = $config.StorageAccountName
        $StorageAccountName = $StorageAccountName.replace('"', "'")

        #LogInfo("Select the target subscription for the current session")
        #Select-AzSubscription -SubscriptionId $SubscriptionId 

        # Register the target storage account with your active directory environment under the target OU (for example: specify the OU with Name as "UserAccounts" or DistinguishedName as "OU=UserAccounts,DC=CONTOSO,DC=COM"). 
        # You can use to this PowerShell cmdlet: Get-ADOrganizationalUnit to find the Name and DistinguishedName of your target OU. If you are using the OU Name, specify it with -OrganizationalUnitName as shown below. If you are using the OU DistinguishedName, you can set it with -OrganizationalUnitDistinguishedName. You can choose to provide one of the two names to specify the target OU.
        # You can choose to create the identity that represents the storage account as either a Service Logon Account or Computer Account (default parameter value), depends on the AD permission you have and preference. 
        # Run Get-Help Join-AzStorageAccountForAuth for more details on this cmdlet.

        LogInfo("Join-AzStorageAccountForAuth...")

        $username = $($config.domainName + "\" + $config.domainJoinUsername)
        $scriptPath = $($PSScriptRoot + "\azfilesEnablement.ps1")
        $scriptBlock = { .\psexec /accepteula -h -u $username -p $domainJoinPassword -c "powershell.exe" "$scriptPath -SubscriptionId $SubscriptionId -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName -AzureAdminUpn $AzureAdminUpn -AzureAdminPassword $AzureAdminPassword" }
        Invoke-Command $scriptBlock -Verbose
        #.\psexec -h -c "powershell.exe" -accepteula -u "gt1027\ssa" -p $password -arguments "Join-AzStorageAccountForAuth -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -DomainAccountType 'ComputerAccount' -OrganizationalUnitName 'Domain Controllers'"
        #Start-Process "ntrights.exe" -ArgumentList "+r SeImpersonatePrivilege -u gt1027\ssa"
        #Start-Process "powershell.exe" -Credential $adminCredential -ArgumentList "-Command & {$ScriptBlock Join}"
    
        #LogInfo("Az files enabled!")
    }
}
