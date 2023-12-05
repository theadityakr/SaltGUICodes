function FirewallState {
    $PublicProfile = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
    if($PublicProfile -like "*0*"){
        $Port = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber | Select-Object PortNumber
        if(netsh advfirewall firewall show rule name="RDP Port $($Port.PortNumber)" -contains "No rules match the specified criteria.")
        {
          netsh advfirewall firewall add rule name="RDP Port $($Port.PortNumber)" dir=in protocol=TCP localport=$Port.PortNumber action=allow  
        }
        & netsh advfirewall set publicprofile state on
        $MSG = "Windows Firewall Public Profile is Enabled and RDP Port $($Port.PortNumber) is Allowed."
        $Body = $VMINFO +  "`r`n" + $MSG
        $Subject = "Windows Firewall Public Profile is disabled on: $Env:ComputerName"
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


function xFirewallState {
    ExecuteFunction -RegKeyName FirewallState -FunctionName $function:FirewallState -IntervalInMins 1440
}





    xFirewallState   # This verify the Firewall Public Profile. Email Subject: Windows Firewall Public Profile is disabled on: