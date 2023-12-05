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



function TerminalCALS {
    $userException =  ExceptionFunction -RegKeyPath "$RegKeyPath"
    Import-module servermanager -ErrorAction SilentlyContinue -Force | Out-Null
    $RDSFeature = (Get-WindowsFeature -name RDS-Licensing).Installed
    If($RDSFeature -like "*True*"){
        Import-Module remotedesktopservices -ErrorAction SilentlyContinue -Force | Out-Null
        Remove-item RDS:\LicenseServer\IssuedLicenses\PerUserLicenseReports\* -Recurse -Confirm:$False -Force | Out-Null
        $OSVersion =  [System.Environment]::OSVersion.Version
        IF(($OSVersion.Major -eq "6") -and ($OSVersion.Minor -le"1")){
            $NewReport = new-item -path RDS:\LicenseServer\IssuedLicenses\PerUserLicenseReports -Scope DOM -Name Report
            $NewReportName = $NewReport.name
            $InstalledLicenseCount = get-item RDS:\LicenseServer\IssuedLicenses\PerUserLicenseReports\$NewReportName\Win2K8-Win2K8R2\InstalledCount
            $TSCAL = $InstalledLicenseCount.CurrentValue
        } Else {
            $fileName = Invoke-WmiMethod Win32_TSLicenseReport -Name GenerateReportEx | Select-Object -ExpandProperty FileName
            $summaryEntries = (Get-WmiObject Win32_TSLicenseReport|Where-Object FileName -eq $fileName).FetchReportSummaryEntries(0,0).ReportSummaryEntries
            $TSCAL = $summaryEntries.InstalledLicenses
        }
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Where-Object {($_.Disabled -notlike "True") -and ($_.Name -notlike "QBDataServiceUser*") -and ($_.Name -notlike "QBPOSDBSrvUser*")  -and ($_.Name -notlike "Summer*")  -and ($_.Name -notlike "spring*") -and  ($userException -notcontains $_.Name)} | Select-Object -ExpandProperty Name
        $UserCount = $LocalUsers | Measure-Object
            if($UserCount.Count -gt $TSCAL){
                $xLocalUsers = @()
                foreach($user in $LocalUsers){
                    $xLocalUsers += "===============`r`n"
                    $xLocalUsers += $user
                    $xLocalUsers += "`r`n"
                }
                $Subject = "Local users are more than Installed TSCAL: $Env:ComputerName"
                if (((Get-WmiObject win32_computersystem).partofdomain -eq $true) -and ($UserCount.Count -gt 0)){
                    foreach($user in $LocalUsers){
                        $AccountDisable=0x0002
                        [ADSI]$LU="WinNT://$ENV:COMPUTERNAME/$user,User"
                        $new=$LU.UserFlags.Value -bor $AccountDisable
                        $LU.put("userflags",$new)
                        $LU.SetInfo()
                    }
                        $MSG = "Found local user active on Domain Join VDI which has been disabled."
                        $Body = $VMINFO +  "`r`n" + $MSG  +  "`r`n" + "TSCAL Count: "+ $TSCAL +  "`r`n"  + "Local User Count: " + [int32]$UserCount.Count + "`r`n"  +  [String]$xLocalUsers
                        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
                } Else {
                    $Body = $VMINFO +  "`r`n"  + "TSCAL Count: "+ $TSCAL +  "`r`n"  + "Local User Count: " + [int32]$UserCount.Count + "`r`n"  +  [String]$xLocalUsers
                    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
                }
             
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

function xTerminalCALS {
    ExecuteFunction -RegKeyName TerminalCALS -FunctionName $function:TerminalCALS -IntervalInMins 1440
}

xTerminalCALS    # This verify TS CALS. Email Subject: Local users are more than Installed TSCAL: