$folderPath = "C:\"

$jsonFiles = Get-ChildItem -Path $folderPath -Filter *.json

foreach ($x in $jsonFiles) {

$file = $x.FullName
$name =  (Get-Item $file).name

$HTTPSStorageHost = "https://prometheuschat.blob.core.windows.net"

$Container = "salt"

$SASToken = "?sp=racwdli&st=2023-12-03T15:30:46Z&se=2023-12-05T15:30:46Z&spr=https&sv=2022-11-02&sr=c&sig=wdFSWFcF5mE4bAqmFfRxFmfgPLYNI3LNlt6jWTHGRvM%3D"

$URI = "$($HTTPSStorageHost)/$($Container)/$($name)$($SASToken)"

$header =@{
  'x-ms-blob-type' = 'BlockBlob'
}

Invoke-RestMethod -Method PUT -Uri $URI -Headers $header -InFile $file

}
