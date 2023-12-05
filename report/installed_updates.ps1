# Get information about installed Windows updates
$hotFixes = Get-HotFix | Select-Object -Property Description, HotFixID, InstalledOn 


$jsonObject = [PSCustomObject]@{
    windows_updates = $hotFixes
}


#$jsonObject | Add-Member -MemberType NoteProperty -Name "windows_updates" -Value $hotFixes
# Specify the path for the output JSON file
$outputFilePath = 'C:\1.json'

$jsonFilePath1 = "C:\1.json"
$jsonObject1 = Get-Content -Path $jsonFilePath1 | ConvertFrom-Json
$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Windows_Updates" -Value $jsonObject.windows_updates
# Convert the installed updates information to JSON and write it to a file
$jsonObject1 | ConvertTo-Json | Out-File -FilePath $outputFilePath


