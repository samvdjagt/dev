$timeInt = (Get-date).TofileTime()
$DeploymentScriptOutputs = @{}
$DeploymentScriptOutputs['keyvaultName'] = \"keyvlt\" + $timeInt
$DeploymentScriptOutputs['componentsName'] = \"comp\" + $timeInt
$DeploymentScriptOutputs['assetsName'] = \"asset\" + $timeInt
$DeploymentScriptOutputs['profilesName'] = \"profil\" + $timeInt
