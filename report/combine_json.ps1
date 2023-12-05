# Paths to the two JSON files to be combined
$jsonFilePath1 = "C:\1.json"
$jsonFilePath2 = "C:\2.json"
$jsonFilePath3 = "C:\3.json"
$jsonFilePath4 = "C:\4.json"

# Read content from the JSON files

$jsonObject1 = Get-Content -Path $jsonFilePath1 | ConvertFrom-Json
$jsonObject2 = Get-Content -Path $jsonFilePath2 | ConvertFrom-Json
$jsonObject3 = Get-Content -Path $jsonFilePath3 | ConvertFrom-Json
$jsonObject4 = Get-Content -Path $jsonFilePath4 | ConvertFrom-Json



$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Base_Machine" -Value $jsonObject2.PhysicalHostName
$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Windows_Updates" -Value $jsonObject3.windows_updates
$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Softwares" -Value $jsonObject4.softwares


$jsonObject1 | ConvertTo-Json | Out-File -FilePath "C:\1.json"

