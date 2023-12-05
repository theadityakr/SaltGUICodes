  Function TSFairSharing {
    Import-module servermanager -ErrorAction SilentlyContinue -Force
    $RDSFeature = (Get-WindowsFeature -name RDS-Licensing).Installed
    If($RDSFeature -like "*True*"){
      $output = ""
      $xBody = @()
      $CPU = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Name 'EnableCPUQuota').EnableCPUQuota
      $Disk = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\Disk" -Name 'EnableFairShare').EnableFairShare
      $NW = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\NetFS" -Name 'EnableFairShare').EnableFairShare
      If($CPU -like "*1*"){
        $output = "Yes"
        $xBody += "EnableCPUQuota is Enabled" + "`r`n"
        <#
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Name 'EnableCPUQuota' -Value 0 -Force -Confirm:$false | Out-Null
        $CPU = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Name 'EnableCPUQuota').EnableCPUQuota
        If($CPU -like "*1*"){
            $output = "Yes"
            $xBody += "Tried Disabling CPUQuota but it failed" + "`r`n"
        } Else {
            $output = "Yes"
            $xBody += "CPUQuota has been disabled reboot may required." + "`r`n"
        }
        #>
      }
      If($Disk -like "*1*"){
        $output = "Yes"
        $xBody += "EnableFairShare on Disk is Enabled" + "`r`n"
        <#
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\Disk" -Name 'EnableFairShare' -Value 0 -Force -Confirm:$false | Out-Null
        $Disk = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\Disk" -Name 'EnableFairShare').EnableFairShare
        If($Disk -like "*1*"){
            $output = "Yes"
            $xBody += "Tried Disabling FairShare on Disk but it failed" + "`r`n"
        } Else {
            $output = "Yes"
            $xBody += "FairShare on Disk has been disabled reboot may required." + "`r`n"
        }
        #>
      }
      If($NW -like "*1*"){
        $output = "Yes"
        $xBody += "EnableFairShare on Network is Enabled" + "`r`n"
        <#
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\NetFS" -Name 'EnableFairShare' -Value 0 -Force -Confirm:$false | Out-Null
        $Disk = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\NetFS" -Name 'EnableFairShare').EnableFairShare
        If($Disk -like "*1*"){
            $output = "Yes"
            $xBody += "Tried Disabling FairShare on Network but it failed" + "`r`n"
        } Else {
            $output = "Yes"
            $xBody += "FairShare on Network has been disabled reboot may required." + "`r`n"
        }
        #>
      }
      if($output -like "*Yes*"){
        $Body =  $VMINFO +  "`r`n" + $xBody
        $Subject = "TS Fair Sharing is enabled On: $Env:ComputerName"
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
      }
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



  function xTSFairSharing {
    ExecuteFunction -RegKeyName TSFairSharing -FunctionName $function:TSFairSharing -IntervalInMins 1440
}




    xTSFairSharing   # This verify if TS Fair Share is enabled. Email Subject: TS Fair Sharing is enabled On: