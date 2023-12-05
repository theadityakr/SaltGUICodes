$jsonObject = salt-call --out=json grains.items | ConvertFrom-Json

# Convert JSON string to a PowerShell object
#$jsonObject = $jsonString | ConvertFrom-Json

# Function to remove a specific key from a nested JSON object
function Remove-JsonKey {
    param (
        [Parameter(Mandatory=$true)]
        [object]$JsonObject,
        
        [Parameter(Mandatory=$true)]
        [string]$KeyToRemove
    )

    $JsonObject.PSObject.Properties.Remove($KeyToRemove) | Out-Null

    foreach ($property in $JsonObject.PSObject.Properties) {
        if ($property.Value -is [System.Management.Automation.PSCustomObject]) {
            Remove-JsonKey -JsonObject $property.Value -KeyToRemove $KeyToRemove
        }
    }
}


$keysToRemove = @("localhost","pending_reboot",'biosversion', 'disks', 'cwd', 'master','server_id', 'fqdn', 'ip4_interfaces','locale_info','pythonpath','path','saltpath',"ip_interfaces","fqdns","hwaddr_interfaces","ip6_interfaces","fqdn_ip4","fqdn_ip6","ip_interfaces","num_gpus","gpus","kernel","nodename","kernelrelease","kernelversion","os_family","osservicepack","osmanufacturer","manufacturer","productname","serialnumber","osfullname","timezone","uuid","windowsdomaintype","motherboard","virtual","ps","osrelease_info","osfinger","init","systempath","pythonexecutable","pythonversion","saltversion","saltversioninfo","zmqversion","ssds","shell","transactional","efi","efi-secure-boot","groupname","pid")


# Remove specified keys from the JSON object
foreach ($key in $keysToRemove) {
        Remove-JsonKey -JsonObject $jsonObject -KeyToRemove $key
}

$localContent = $jsonObject.local
# Specify the path for the output JSON file
$outputFilePath = 'C:\1.json'

# Convert the installed updates information to JSON and write it to a file
$localContent | ConvertTo-Json | Out-File -FilePath $outputFilePath

