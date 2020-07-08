#     [Required]  ${1}  <orgName>        
#     [Required]  ${2}  <projectName>         
#     [Required]  ${3}  <azureAdminUpn>             
#     [Required]  ${4}  <azureAdminPassword>   

az extension add --name azure-devops
az login -u ${3} -p ${4}
az pipelines create --name "WVD Quickstart" --organization "https://dev.azure.com/${1}" --project ${2} --repository ${2} --repository-type "tfsgit" --branch "master" --yml-path "QS-WVD/pipeline.yml"
