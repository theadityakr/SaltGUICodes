$folderPath = "C:\"

$jsonFiles = Get-ChildItem -Path $folderPath -Filter *.json

foreach ($x in $jsonFiles) {

$file = $x.FullName
$name =  (Get-Item $file).name

$HTTPSStorageHost = "https://dfdffdffdf"

$Container = "salt"

$SASToken = "?dfvdfdff"

$URI = "$($HTTPSStorageHost)/$($Container)/$($name)$($SASToken)"

$header =@{
  'x-ms-blob-type' = 'BlockBlob'
}

Invoke-RestMethod -Method PUT -Uri $URI -Headers $header -InFile $file

}
