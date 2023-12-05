# Get the content of a file
$fileContent = Get-Content -Path "C:\1.json" | ConvertFrom-Json 

# Output the content
Write-Output $fileContent

