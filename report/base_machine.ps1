# Specify the registry key path
$registryKeyPath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'

# Specify the specific value name
$valueName = 'PhysicalHostName'

# Get the value from the registry key
$registryValue = Get-ItemProperty -Path $registryKeyPath | Select-Object -ExpandProperty $valueName

# Specify the path for the output JSON file
$outputFilePath = 'C:\1.json'

# Create an object with the registry value
$jsonObject = @{
    PhysicalHostName = $registryValue
}

$jsonFilePath1 = "C:\1.json"
$jsonObject1 = Get-Content -Path $jsonFilePath1 | ConvertFrom-Json
$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Base_Machine" -Value $jsonObject.PhysicalHostName

# Convert the object to JSON and write it to a file
$jsonObject1 | ConvertTo-Json | Out-File -FilePath $outputFilePath

