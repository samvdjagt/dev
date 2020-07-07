@{
    # General Information #
    # =================== #
    # Environment
    subscriptionId                        = ""      # user input
    tenantId                              = ""      # from serviceprincipal
    objectId                              = ""      # from serviceprincipal
    
    # Pipeline
    WVDDeploymentServicePrincipal         = "Attempt"              # default
    
    # Components
    componentStorageContainerName         = "components"                        # default
    componentStorageAccountName           = "componentstorage07072020"          # generated with date & time to ensure uniqueness
  
    # ResourceGroups
    location                              = "eastus"                            # user input
    resourceGroupName                     = "QS-WVD-TEST5"                         # default
    wvdMgmtResourceGroupName              = "QS-WVD-MGMT-RG"                    # default
    #######################

    # Key Vault related #
    # ================= #  
    keyVaultName                          = "WVDKeyVault07072020"               # default
    # wvdKeyVaultAccessGroupName            = "KeyVaultAccessGroup"
    #####################
    
    # Storage related #
    # =============== #
    wvdAssetsStorage                      = "assetsstorage07072020"             # generated with date & time to ensure uniqueness
    profilesStorageAccountName            = "profilesstorage07072020"           # generated with date & time to ensure uniqueness
    storageAccountSku                     = "Standard_LRS"                      # default
    storageAccountAuthentication          = "AD"                                # default for now, could become user input
    profilesShareName                     = "wvdprofiles"                       # default
    # fileshareUsersGroupName               = 
    # fileShareName                         = 
    ###################

    # Host pool related #
    # ================== #
    hostpoolName                          = "QS-WVD-HP2"                         # default
    hostpoolType                          = "Pooled"                            # default
    maxSessionLimit                       = 16                                  # default
    loadBalancerType                      = "BreadthFirst"                      # default
    vmNamePrefix                          = "QS-WVD-VM"                         # default
    vmSize                                = "Standard_D2s_v3"                   # default
    vmNumberOfInstances                   = 2                                   # default
    vmInitialNumber                       = 1                                   # default
    diskSizeGB                            = 128                                 # default
    vmDiskType                            = "Premium_LRS"                       # default
    domainJoinUser                        = "ssa@gt1027.onmicrosoft.com"        # user input
    domainName                            = "gt1027.onmicrosoft.com"            # taken from domainJoinUser
    adminUsername                         = "ssa"                               # taken from domainJoinUser
    AdminPasswordSecret                   = "ssa-Password"                      # user input
    computerName                          = "adVm"
    vnetName                              = "adVnet"                            # search for existing vnet
    vnetResourceGroupName                 = "AD"                                # search for existing vnet resource group
    subnetName                            = "adSubnet"                          # search for existing subnet in existing vnet
    enablePersistentDesktop               = $false                              # default
    ######################

    # App group related #
    # ================== #
    appGroupName                          = "QS-WVD-RAG"                        # default
    DesktopAppGroupName                   = "QS-WVD-DAG"                        # default
    targetGroup                           = "WVDUsers"                              # name of user group with associated principalId below
    newUserName                           = "WVDUser001"
    principalIds                          = "26940b0f-a17f-48c1-a575-89b2975f5c38"  # from user input on users to assign
    workSpaceName                         = "QS-WVD-WS2"                         # default
    workspaceFriendlyName                 = "WVD Workspace"                     # default
    ######################

    # Imaging related #
    # ================ #
    imagingResourceGroupName              = "QS-WVD-IMG-RG"                     # default
    imageTemplateName                     = "QS-WVD-ImageTemplate"              # default
    imagingMSItt                          = "[imagingMSItt]"                    # UNSURE
    sigGalleryName                        = "[sigGalleryName]"                  # UNSURE
    sigImageDefinitionId                  = "<sigImageDefinitionId>"            # supposedly filled in by pipeline
    imageDefinitionName                   = "W10-20H1-O365"                     # default
    osType                                = "Windows"                           # default
    publisher                             = "MicrosoftWindowsDesktop"           # default
    offer                                 = "office-365"                        # default
    sku                                   = "20h1-evd-0365"                     # default
    imageVersion                          = "latest"                            # default
    ######################

    automationAccountName                 = "[automationAccountName]"           # UNSURE


    # Authentication related
    # ==================== #
    identityApproach                      = "AD" # (AD or AADDS)                # default for now, could become user input
    
    # Only required for AD
    ADWVDSecretsGroupName                 = "WVDSecrets"                        # default
    
    # Only required for AADDS
    # domainJoinPrincipalName               = "domainJoinUser@cedward.onmicrosoft.com"
    ########################
}
