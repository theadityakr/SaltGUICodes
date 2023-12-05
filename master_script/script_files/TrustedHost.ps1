function TrustedHost {
    $TrustedHost = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value | Measure-Object -Word
    If($TrustedHost.Words -gt 0){
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force -Confirm:$false | Out-Null
        $Body =  $VMINFO +  "`r`n" + "Trusted Host Values: $TrustedHost"
        $Subject = "WinRM Trusted Host Modified on: $Env:ComputerName"
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
    } 
}


#Email Settings
$EmailTo = "Alerts@apps4rentmonitoring.com"
$EmailFrom = "No-Reply@Apps4Rent.com"
$SMTPServer = "SPAlerts.hostallapps.com"
$IPADDRESS = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').IPAddress
$Manufacturer = (Get-WmiObject win32_computersystem).manufacturer
if($Manufacturer -eq 'Xen'){
$VMHOST = "Xen"
$VMNAMEONHOST = $ENV:COMPUTERNAME
} Else {
$VMHOST = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")
$VMNAMEONHOST = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("VirtualMachineName")
}
$VMINFO = $Env:ComputerName +  "`r`n" + $IPADDRESS + "`r`n" + $VMHOST + "`r`n" + $VMNAMEONHOST + "`r`n"
$DL = "\\FTP.globalhostedcloud.com\Share"
$UN = 'WakeUpCall'
$PD = "VwAzACEAYwAwAG0AZQBAADIAQAAxADkAJABeAEAAIwAmAA=="


function xTrustedHost {
    ExecuteFunction -RegKeyName TrustedHost -FunctionName $function:TrustedHost -IntervalInMins 5
}






    #xTrustedHost     # This verify if WinRM Trusted Host Modified. Email Subject: WinRM Trusted Host Modified on:

    