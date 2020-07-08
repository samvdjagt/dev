[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # [Parameter(Mandatory = $true)]
    # [ValidateNotNullOrEmpty()]
    # [string] $storageAccountKey,

    [Parameter(Mandatory = $false)]
    [Hashtable] $DynParameters,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigurationFileName = "users.parameters.json"
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
Set-Logger "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\executionLog\UserConfig" # inside "executionCustomScriptExtension_$scriptName_$date.log"

LogInfo("###################")
LogInfo("## 0 - LOAD DATA ##")
LogInfo("###################")
#$storageaccountkey = $DynParameters.storageaccountkey

$PsParam = Get-ChildItem -path "_deploy" -Filter $ConfigurationFileName -Recurse | sort -Property FullName
$ConfigurationFilePath=$PsParam.FullName
#$ConfigurationFilePath= Join-Path $PSScriptRoot $ConfigurationFileName

$ConfigurationJson = Get-Content -Path $ConfigurationFilePath -Raw -ErrorAction 'Stop'

try { $UserConfig = $ConfigurationJson | ConvertFrom-Json -ErrorAction 'Stop' }
catch {
    Write-Error "Configuration JSON content could not be converted to a PowerShell object" -ErrorAction 'Stop'
}

LogInfo("##################")
LogInfo("## 1 - EVALUATE ##")
LogInfo("##################")
foreach ($config in $UserConfig.userconfig) {
    $credential = New-Object System.Management.Automation.PsCredential("gt1027.onmicrosoft.com" + "\" + "ssa", (ConvertTo-SecureString "Edno1Nula0!!" -AsPlainText -Force))
    Loginfo("Attempting to log in with $config.adminPassword " + "$config.domain" + "\" + "$config.adminUsername")
    $Session = new-PSSession -ComputerName $env:computername -Credential $credential
    Invoke-Command -Session $Session { $Session2 = new-PSSession -ComputerName "adVm" -Credential $credential }

    if ($config.createGroup) {
        LogInfo("###########################")
        LogInfo("## 2 - Create user group ##")
        LogInfo("###########################")
        LogInfo("Trigger user group creation")

          
        $userGroupName = $config.targetGroup
        $domainName = $config.domain
        $passWord = $config.password

        LogInfo("Create user group...")

        Invoke-Command -Session $Session { Invoke-Command -Session $Session2 { New-ADGroup `
        -SamAccountName $userGroupName `
        -Name "$userGroupName" `
        -DisplayName "$userGroupName" `
        -GroupScope "Global" `
        -GroupCategory "Security" -Verbose } }

        LogInfo("Create user group completed.")
    }
    
    if ($config.createUser) {
        LogInfo("########################")
        LogInfo("## 2 - Create user    ##")
        LogInfo("########################")
        LogInfo("Trigger user creation")

        
        $userName = $config.userName
        $domainName = $config.domain
        $passWord = $config.password

        LogInfo("Create user...")

        Invoke-Command -Session $Session { Invoke-Command -Session $Session2 { New-ADUser `
        -SamAccountName $userName `
        -UserPrincipalName $userName + "@" + $domainName `
        -Name "$userName" `
        -GivenName $userName `
        -Surname $userName `
        -Enabled $True `
        -ChangePasswordAtLogon $True `
        -DisplayName "$userName" `
        -AccountPassword (convertto-securestring $passWord -AsPlainText -Force) -Verbose } }

        LogInfo("Create user completed.")
    }

    if ($config.assignUsers) {
        LogInfo("###############################")
        LogInfo("## 3 - Assign users to group ##")
        LogInfo("###############################")

        LogInfo("Assigning users to group...")
        Invoke-Command -Session $Session { Invoke-Command -Session $Session2 { Add-ADGroupMember -Identity $config.targetGroup -Members $config.userName } }
        LogInfo("User assignment to group completed.")
    }

    if ($config.syncAD) {
        LogInfo("#############################################")
        LogInfo("## 4 - Sync new users & group with AD Sync ##")
        LogInfo("#############################################")

        Invoke-Command -Session $Session { Invoke-Command -Session $Session2 { Import-Module ADSync } }
        Invoke-Command -Session $Session { Invoke-Command -Session $Session2 { Start-ADSyncSyncCycle -PolicyType Delta -Verbose } }
    }
}
