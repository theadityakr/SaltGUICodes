# Get all installed programs, their versions, and installation dates from the registry
$installedPrograms = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
                     Where-Object { $_.DisplayName -and $_.DisplayVersion -and $_.InstallDate } |
                     Select-Object DisplayName, DisplayVersion, @{Name='InstallDate'; Expression={[System.DateTime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)}}



$jsonObject = [PSCustomObject]@{
    softwares = $installedPrograms
}


#$jsonObject | Add-Member -MemberType NoteProperty -Name "windows_updates" -Value $hotFixes
# Specify the path for the output JSON file
$outputFilePath = 'C:\1.json'

$jsonFilePath1 = "C:\1.json"
$jsonObject1 = Get-Content -Path $jsonFilePath1 | ConvertFrom-Json
$jsonObject1 | Add-Member -MemberType NoteProperty -Name "Softwares" -Value $jsonObject.softwares

# Convert the installed updates information to JSON and write it to a file
$jsonObject1 | ConvertTo-Json | Out-File -FilePath $outputFilePath


