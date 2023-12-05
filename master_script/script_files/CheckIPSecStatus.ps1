<#
    This is Master File.
    v3 Added Chrome and Firefox update script.
    v4 Added QBDataServiceUser under TSCal exception; Modify email body in NetBIOS;Added new Monitoring xWinDefend; 
    Added new Monitoring xQBUpdate; Windows Publich Profile enabled with RDP port allowed; SMBv1 is Disabled; Added Fix for SCCMComm;
    Added Fix for SCCMINS; Added Fix for DefINS; Added fix for DefLQS; Added Fix for DefAVSA;Added new Monitoring xOfficeLicenseCheck.
    v5 Corrected the DNS Suffix Name in SCCM Installation; updated the Install process and error handling.
    v6 VSCode added junk char in SMB which is removed.
    v7 Defender Realtime Protection Notification disabled.
    v8 Updated DefAVSA block to run on Monday and Tuesday. Also change Update service status to Disable.
    v9 Updated the UpdateMaster and Updatefirefox due to incorrect copy source. Updated xupdatechrome and xupdatefirefox execution time
    v10 Update QBUpdate function with lastest script. V10.1 Updated QBPatch2.exe find process.
    v11 Change Windows update service to manual.
    v12 Added SCEP Disable by admin review via regedit.
    v13 Added Network Discovery Disable rule. xDisableNetworkDiscovery
    V14 xDefAVSA is disabled due to Update Service Issue.
    v15 Enabled xDefAVSA. Changed DefAVSA Days from 7 to 2 and added code to download and install update from internet if its older than 2days.
    v16 xUpdateGHCSCCMHostFile added this new block on 11th Feb to avoid network issue. 
    SCCMComm Updated this to trigger machine policy scan and restart service. xSCCMComm Change duration from 2hrs to 12hrs
    v17 Updated SCCMIns Function to download via HTTP instead of SMB
    v18 Updated SCCMIns to run if uptime is above 2hrs.
    v19 Added xUserLockOut function Added new update fucntion. Added xNewUpdateMaster new function for HTTP based update.
    v20 updated TSCAL to exclude QBPOSDBSrvUser user.
    v21 Added xNewLocalUserCheck  # Detects local user created in last 24hrs.
    v22 Updated UpdateGHCSCCMHostFile to remove Hostfile for SCCM due to implementation of IPSec. Added AddIPSecPolicy. Added RenameSupportUser.
    v23 Added CheckIPSecStatus to check IPSec Status
    v24 Added RDP SSL update as  xUpdateRDPCertificate.
    v25 Updated Prometheus Installation & changed frequency for checking multiple parameters to avoid bulk emails
    v26 Commented Send email in OfficeLicenseCheck. Updated QBUpdate Script to check install status. Install PMPAgent Added.
    v27 Added xCheckJunctionPoints & xUpdateQBFileSizePrometheus. Updated QB edition for updates.
    v28 xRansomwareChecklist #Added few monitoring for security checks. Updated PMP IP for IPSec.
    v29 xCleanupDisk added this to cleanup disk.
    v30 xRestartPrintSpooler added to restart print spooler service. Updated QBUpdate function with QB 2023 details.
    v31 xRDSCALReport added to calculate RDS CAL. Also updated QBupdate for QB2022 & QB2023 issue.
    v32 Updated ExecuteFunction to update IntervalInMins if its mismatch. Also Fixed issue with RDSCALReport. Updated QB Execution time window from 1:00 to 3:00 to 22:00 to  3:00. 
    v33 Updated SCCM Server Name. Changed Master script update schedule to 12hrs. Updated RDSCAL Reporting module & also execution time
    v34 Updated AddIPSecPolicy to add 10.100.115.156 IP in allow list. Added xStopUnwantedServices To Stop unwanted services.
    v35 Updated CHeckIPSec with additional Rule
#>



function Apps4RentRegKey {
    [CmdletBinding()]
      param (
        [Parameter(Mandatory=$true)]
        $Name
      )
        $RegRoot = "HKLM:\System\Apps4Rent"
        $TestRegRoot = Test-Path -Path $RegRoot
        If($TestRegRoot -like "*False*"){
            New-Item $RegRoot -Force | Out-Null
        }
        $NewRegKey = "$RegRoot\$Name"
        $TestNewRegKey = Test-Path -Path $NewRegKey  
        If($TestNewRegKey -like "*False*"){
            New-Item $NewRegKey -Force | Out-Null
            New-ItemProperty -Path $NewRegKey -Name Enabled -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $NewRegKey -Name IntervalInMins -Value 0 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $NewRegKey -Name LastRun -Value (Get-Date) -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $NewRegKey -Name NextRun -Value (Get-Date) -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $NewRegKey -Name Exception -Value 0 -PropertyType MultiString -Force | Out-Null
        } Else {
            $NewRegKeyEnabled = (Get-ItemProperty -Path $NewRegKey).Enabled
            If($null -eq $NewRegKeyEnabled){
                New-ItemProperty -Path $NewRegKey -Name Enabled -Value 1 -PropertyType DWORD -Force | Out-Null
            }
            $NewRegKeyIntervalInMins = (Get-ItemProperty -Path $NewRegKey).IntervalInMins
            If($null -eq $NewRegKeyIntervalInMins){
                New-ItemProperty -Path $NewRegKey -Name IntervalInMins -Value 0 -PropertyType DWORD -Force | Out-Null
            }
            $NewRegKeyLastRun = (Get-ItemProperty -Path $NewRegKey).LastRun
            If($null -eq $NewRegKeyLastRun){
                New-ItemProperty -Path $NewRegKey -Name LastRun -Value (Get-Date) -PropertyType String -Force | Out-Null
            }
            $NewRegKeyNextRun = (Get-ItemProperty -Path $NewRegKey).NextRun
            If($null -eq $NewRegKeyNextRun){
                New-ItemProperty -Path $NewRegKey -Name NextRun -Value (Get-Date) -PropertyType String -Force | Out-Null
            }
            $NewRegKeyException = (Get-ItemProperty -Path $NewRegKey).Exception
            If($null -eq $NewRegKeyException){
                New-ItemProperty -Path $NewRegKey -Name Exception -Value 0 -PropertyType MultiString -Force | Out-Null
            }
        }
        Return $NewRegKey
  }







function ExecuteFunction {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,mandatory=$true)]
        $RegKeyName,
        [Parameter(Position=1,mandatory=$true)]
        [scriptblock]$FunctionName,
        [Parameter(Position=2,mandatory=$true)]
        $IntervalInMins,
        [Parameter(Position=3,mandatory=$false)]
        [DateTime]$NextRun
    )
    
    $RegKeyPath = Apps4RentRegKey -Name $RegKeyName
    $xRegEnabled = (Get-ItemProperty -Path $RegKeyPath).Enabled
    if($xRegEnabled -like "*1*"){
        $xRegIntervalInMins = (Get-ItemProperty -Path $RegKeyPath).IntervalInMins
        $xRegNextRun = (Get-ItemProperty -Path $RegKeyPath).NextRun
        $xRegLastRun = (Get-ItemProperty -Path $RegKeyPath).LastRun
        $LastRunDate = [datetime]$xRegLastRun
        $CurrentTime = Get-Date
        $NextRun = [datetime]$xRegNextRun
        $xLastRunDate = $CurrentTime.AddMinutes(-11520)
        If($xRegIntervalInMins -eq 0 ){
            Set-ItemProperty -Path $RegKeyPath -Name IntervalInMins -Value $IntervalInMins -Force | Out-Null
        }
        If($xRegNextRun -eq '0'){
            $FunctionName.Invoke()
            $xRegIntervalInMins = (Get-ItemProperty -Path $RegKeyPath).IntervalInMins
            $CurrentTime = Get-Date
            $NextTime =  $CurrentTime.AddMinutes($xRegIntervalInMins)
            Set-ItemProperty -Path $RegKeyPath -Name NextRun -Value $NextTime -Force | Out-Null
            Set-ItemProperty -Path $RegKeyPath -Name LastRun -Value $CurrentTime -Force | Out-Null
        } Elseif ($CurrentTime -ge $NextRun){
            $FunctionName.Invoke()
            $NextTime =  $CurrentTime.AddMinutes($xRegIntervalInMins)
            Set-ItemProperty -Path $RegKeyPath -Name NextRun -Value $NextTime -Force | Out-Null
            Set-ItemProperty -Path $RegKeyPath -Name LastRun -Value $CurrentTime -Force | Out-Null
        } Else {
                if ($LastRunDate -le $xLastRunDate) {
                    $FunctionName.Invoke()
                    $NextTime =  $CurrentTime.AddMinutes($xRegIntervalInMins)
                    Set-ItemProperty -Path $RegKeyPath -Name NextRun -Value $NextTime -Force | Out-Null
                    Set-ItemProperty -Path $RegKeyPath -Name LastRun -Value $CurrentTime -Force | Out-Null   
                }
            }
        }
        if($xRegIntervalInMins -ne $IntervalInMins ){
            Set-ItemProperty -Path $RegKeyPath -Name IntervalInMins -Value $IntervalInMins -Force | Out-Null
        }
    }







    

function   ExceptionFunction {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,mandatory=$true)]
        $RegKeyPath
    )
    $RegString = Get-ItemProperty -Path "$RegKeyPath" -Name Exception | Select-Object -ExpandProperty Exception
    $KeysArray = @()
    Foreach ($line in $RegString)
    {
    [array]$linedata = $line.Split("-")
    $KeysArray += $linedata
    }
    Return $KeysArray
}





function CheckIPSecStatus {
    $Policy = netsh ipsec static show policy name=Policy_Block-Range | findstr Policy
    $Policy = $Policy -replace (" ","")
    if($Policy -ne "PolicyName:Policy_Block-Range"){
        $App =Get-WmiObject -Class "Win32Reg_AddRemovePrograms" | Select-Object DisplayName | Where-Object {($_.DisplayName -like "*SharePoint*") -or ($_.DisplayName -like "*Exchange*") -or ($_.DisplayName -like "*Xeams*")}
        if(!$App){
            if ((Get-WMIObject win32_computersystem).partofdomain -eq $true){
                $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
                    if(($Domain -like "VDI.Dataoncloud*") -or ($Domain -like "VDI.Hostingcloudapp*") -or ($Domain -like "*mycitrix*")){

                        $MSG = "IPSec Policy Not Configured"
                        $Subject = "IPSec Policy Not Configured: $ENV:computername"
                        $Body = $VMINFO +  "`r`n" + $MSG  +  "`r`n"
                        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
                    }

                } Else{
                    $MSG = "IPSec Policy Not Configured"
                    $Subject = "IPSec Policy Not Configured: $ENV:computername"
                    $Body = $VMINFO +  "`r`n" + $MSG  +  "`r`n"
                    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
                }
            } 
        }
        $Status = netsh ipsec static show policy name=Policy_Block-Range | findstr Assign
        $Status = $Status -replace (" ","")
        If($Status -eq "Assigned:NO"){
        $Subject = "IPSec Policy Not Assigned: $ENV:computername"
        $MSG = "IPSec Policy Not Assigned"
        $Body = $VMINFO +  "`r`n" + $MSG  +  "`r`n"
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
    }
    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.145 protocol=tcp srcport=0 dstport=0 | Out-Null
    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=38.126.136.145 dstaddr=Me protocol=tcp srcport=0 dstport=0 | Out-Null
    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=198.77.13.104 protocol=tcp srcport=0 dstport=0 | Out-Null
    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=198.77.13.104 dstaddr=Me protocol=tcp srcport=0 dstport=0 | Out-Null

    $Policy = netsh ipsec static show policy name=Policy_Block-Range | findstr Policy
    $Policy = $Policy -replace (" ","")
    if($Policy -eq "PolicyName:Policy_Block-Range"){
        #$Policy 
        $IPADDRESS = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "169.254.*"} | Select IPAddress 
        Foreach ($IP in $IPADDRESS){
            $xIP = $IP.IPAddress
            & netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=$xIP protocol=tcp srcport=0 dstport=0 | Out-Null
            & netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=$xIP dstaddr=Me protocol=tcp srcport=0 dstport=0 | Out-Null
        }

        if ((Get-WMIObject win32_computersystem).partofdomain -eq $true){
            $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
                if(($Domain -like "VDI.Dataoncloud*") -or ($Domain -like "VDI.Hostingcloudapp*") -or ($Domain -like "*mycitrix*")){

                    if( ($env:COMPUTERNAME -ne "LicensingServervdidc2019hc") -or ($env:COMPUTERNAME -ne "VDIDC04HC") -or ($env:COMPUTERNAME -ne "VDIDC05HC") -or ($env:COMPUTERNAME -ne "VDIDC05") -or ($env:COMPUTERNAME -ne "CTXDC") -or ($env:COMPUTERNAME -ne "CTXDC03") -or ($env:COMPUTERNAME -ne "CTXDC08") -or ($env:COMPUTERNAME -ne "CTXALL") -or ($env:COMPUTERNAME -ne "CTXSQL")){
                    Write-Host $env:COMPUTERNAME "Is in $Domain"
                   
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.15 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.12 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.79 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.101.26 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.131 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.103.13 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.53 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.104.7 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.114.8 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.116.252 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.108.254 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.13 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.14 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.14 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.194 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.116.249 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.250 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.152 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.101.159 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.239 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.103.203 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.105.183 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.104.96 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.108.11 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.15 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.101.81 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.154 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.114.160 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.195 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.10.7.67.245 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.199 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.83 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.9 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.104.9 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.108.8 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.114.40 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.116.250 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.200 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.104.34 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.34 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.43 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.114.34 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.116.43 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.96 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.196 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.73 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.150 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.107 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.150 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.18 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.159 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.101 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.74 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.26 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.52 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.31 protocol=tcp srcport=0 dstport=0
                    netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=127.0.0.1 protocol=tcp srcport=0 dstport=0
                    
                }

            }
        } Else{
            Write-Host $env:COMPUTERNAME "Is workgroup"
            
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.15 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.67.12 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.126.136.79 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.101.26 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.100.131 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.103.13 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.102.53 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.104.7 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.114.8 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.116.252 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=10.100.108.254 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.13 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=38.107.69.14 protocol=tcp srcport=0 dstport=0
            netsh ipsec static add filter filterlist=Allow-APM-SCCM srcaddr=Me dstaddr=127.0.0.1 protocol=tcp srcport=0 dstport=0
            

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

  function xCheckIPSecStatus {
    ExecuteFunction -RegKeyName CheckIPSecStatus -FunctionName $function:CheckIPSecStatus -IntervalInMins 1440
  }



      xCheckIPSecStatus #Check IPSec Status