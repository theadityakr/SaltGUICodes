# PowerShell script to create a text file in C:\

# Define the file path
$filePath = "C:\example.txt"

# Content to be written to the file
$fileContent = @"
This is a sample text file created using PowerShell.
You can add more content here.
"@

# Create the text file
$fileContent | Out-File -FilePath $filePath -Force

Write-Host "Text file created at: $filePath"

