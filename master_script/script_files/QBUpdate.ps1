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



Function QBUpdate {
    $ScriptBlock = {
        $DL = "\\FTP.globalhostedcloud.com\Share"
        $xUN = 'WakeUpCallRight'
        $xPD = "VwAzACEAYwAwAG0AZQBAADIAQAAyAEAAJABeAEAAIwAmAA=="
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
        $LogFilePath = "C:\Windows\System32\Sysprep\Apps4Rent\"
        $LogFileFormat = "QBLog.txt"
        If ((Test-Path -Path $LogFilePath -PathType Container) -ne 'true' ){
        New-Item -Path $LogFilePath  -ItemType directory | Out-Null
        }
        $logfile = $LogFilePath + $LogFileFormat
        Write-Output "$(Get-Date -Format s) : Starting the script execution" | Out-File -FilePath $logfile -Append -Force | Out-Null
        $QB = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Quickbook*" } | Select-Object DisplayName)
        If($QB -eq $null){
          Write-Output "$(Get-Date -Format s) : No Quickbooks is installed." | Out-File -FilePath $logfile -Append -Force | Out-Null
          $InstallStatus = "QBNotInstall"
        } Else {
          Write-Output "$(Get-Date -Format s) : Quickbooks is installed." | Out-File -FilePath $logfile -Append -Force | Out-Null
          $InstallStatus = "QBIsInstall"
        }
        $update = ""
        $Body = @()
        $Body += $VMINFO + "`r`n"
        #QB update check function
        function QB_update_check {
        [CmdletBinding()]
            param (
            [Parameter(Mandatory=$true)]
            $qbpt,
            [Parameter(Mandatory=$true)]
            $qbpt2
            )
            $patchFilepath = Get-ChildItem -Path $qbpt -Recurse -Force | Where-Object {$_.Name -eq "qbpatch2.exe"}
            if((Test-Path $patchFilepath.FullName) -ne "True"){
              Write-Output "$(Get-Date -Format s) : $($patchFilepath.FullName) doesn't exist" | Out-File -FilePath $logfile -Append -Force | Out-Null
            } Else {
              $Arg = "/q  /A /P " +"$qbpt2"
              taskkill /IM QBW32.EXE /F | Out-Null
              taskkill /IM QBW.EXE /F | Out-Null
              Start-Process "$qbpt2\QBUpdateUtility.bat" -NoNewWindow
              Write-Output "$(Get-Date -Format s) : QBW32.EXE is killed." | Out-File -FilePath $logfile -Append -Force | Out-Null
              Start-Process $patchFilepath.FullName -ArgumentList $arg -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
              Write-Output "$(Get-Date -Format s) : $($patchFilepath.FullName) is started and going in sleep for 180sec." | Out-File -FilePath $logfile -Append -Force | Out-Null
              Start-Sleep -s 180 | Out-Null
              taskkill /IM qbpatch2.exe /F | Out-Null
              taskkill /IM qbpatch.exe /F | Out-Null
              $xBody = $patchFilepath.FullName
              $update = "UpdateInstalled"
            }
        Return $xBody,$Update
        }
        #QB update check
        foreach ($QB in (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Quickbooks *" } | Select-Object DisplayName)) {
        $QB = $QB.DisplayName
        if ($QB -like "*2015*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2015\Components\DownloadQB25" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2015"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2016*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2016\Components\DownloadQB26" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2016"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2017*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2017\Components\DownloadQB27" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2017"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2018*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2018\Components\DownloadQB28" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2018"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2019*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2019\Components\DownloadQB29" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2019"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2020*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2020\Components\DownloadQB30" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2020"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2021*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2021\Components\DownloadQB31" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2021"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2022*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2022\Components\DownloadQB32" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2022"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*2023*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2023\Components\DownloadQB33" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks 2023"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*15.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 15.0\Components\DownloadQB25" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 15.0"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*16.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 16.0\Components\DownloadQB26" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 16.0"
            $Body += $xBody + "`r`n"
            }
        if ($QB -like "*17.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 17.0\Components\DownloadQB27" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 17.0"
            $Body += $xBody + "`r`n"
        }
        if ($QB -like "*18.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 18.0\Components\DownloadQB28" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 18.0"
            $Body += $xBody + "`r`n"
        }
        if ($QB -like "*19.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 19.0\Components\DownloadQB29" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 19.0"
            $Body += $xBody + "`r`n"
        }
        if ($QB -like "*20.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 20.0\Components\DownloadQB30" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 20.0"
            $Body += $xBody + "`r`n"
        }
        if ($QB -like "*21.0*") {
            $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 21.0\Components\DownloadQB31" -qbpt2 "C:\Program Files (x86)\Intuit\QuickBooks Enterprise Solutions 21.0"
            $Body += $xBody + "`r`n"
        }
        }
      
        # QB2022
      if (Test-Path "C:\ProgramData\Intuit\QuickBooks 2022\Components\DownloadQB32"){
          $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2022\Components\DownloadQB32" -qbpt2 "C:\Program Files\Intuit\QuickBooks 2022"
          $Body += $xBody + "`r`n"
      }
      if (Test-Path "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 22.0\Components\DownloadQB32"){
          $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 22.0\Components\DownloadQB32" -qbpt2 "C:\Program Files\Intuit\QuickBooks Enterprise Solutions 22.0"
          $Body += $xBody + "`r`n"
      }
  
        # QB2023
        if (Test-Path "C:\ProgramData\Intuit\QuickBooks 2023\Components\DownloadQB33"){
          $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks 2023\Components\DownloadQB33" -qbpt2 "C:\Program Files\Intuit\QuickBooks 2023"
          $Body += $xBody + "`r`n"
      }
      if (Test-Path "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 23.0\Components\DownloadQB33"){
          $xBody,$Update = QB_update_check -qbpt "C:\ProgramData\Intuit\QuickBooks Enterprise Solutions 23.0\Components\DownloadQB33" -qbpt2 "C:\Program Files\Intuit\QuickBooks Enterprise Solutions 23.0"
          $Body += $xBody + "`r`n"
      }
  
  
        $xxBody = $Body | Out-String
        $xSPD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($xPD))
        $pass = ConvertTo-SecureString -AsPlainText $xSPD -Force
        $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $xUN,$pass
        Try{
          New-PSDrive -Name TempS -PSProvider FileSystem -Root "$DL" -ErrorAction Stop -ErrorVariable ERR -Credential $Cred | Out-Null
          If($ERR -eq $Null){
            Write-Output "$(Get-Date -Format s) : Able to access $DL" | Out-File -FilePath $logfile -Append -Force | Out-Null
          }
        }Catch{
          Write-Output "$(Get-Date -Format s) : Fail to access $DL and error is $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Force | Out-Null
            
        }
        $Date = Get-date -Format yyyyMMdd
        If ((Test-Path -Path $DL\QBReports -PathType Container) -ne 'true' ){
        New-Item -Path $DL\QBReports  -ItemType directory | Out-Null
        Write-Output "$(Get-Date -Format s) : New Folder is created as $DL\QBReports" | Out-File -FilePath $logfile -Append -Force | Out-Null
        }
        If ((Test-Path -Path $DL\QBReports\$Date -PathType Container) -ne 'true' ){
        New-Item -Path $DL\QBReports\$Date -ItemType directory | Out-Null
        Write-Output "$(Get-Date -Format s) : New Folder is created as $DL\QBReports\$Date" | Out-File -FilePath $logfile -Append -Force | Out-Null
        }
        $QBInstallStatus = $InstallStatus
        $QBUpdateStatus = $update
        If($QBInstallStatus -like "*QBNotInstall*"){
            $File = $env:COMPUTERNAME+"_"+$VMHOST+"_"+$QBInstallStatus+".txt"
            Write-Output "No QB Installed."
        } Else {
            $File = $env:COMPUTERNAME+"_"+$VMHOST+"_"+$QBInstallStatus+"_"+$QBUpdateStatus+".txt"
            Write-Output "$(Get-Date -Format s) : Log file name is $File" | Out-File -FilePath $logfile -Append -Force | Out-Null
            Try{
              $xxBody | Out-File -FilePath $DL\QBReports\$Date\$File -Confirm:$false -ErrorAction Stop -ErrorVariable ERR  -Append -Force | Out-Null
              If($ERR -eq $Null){
                Write-Output "$(Get-Date -Format s) : Log file has been created at $DL\QBReports\$Date\$File" | Out-File -FilePath $logfile -Append -Force | Out-Null
              }
            }Catch{
              Write-Output "$(Get-Date -Format s) : Fail to create log file $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Force | Out-Null
                
            }
            If($QBUpdateStatus -ne "UpdateInstalled"){
                Write-Output "$(Get-Date -Format s) : Notification Email has been sent" | Out-File -FilePath $logfile -Append -Force | Out-Null
            } elseif($QB -ne $null){
                Write-Output "$(Get-Date -Format s) : No Quickbooks update found." | Out-File -FilePath $logfile -Append -Force | Out-Null
                Write-Output "No QB updates found"
                }
        }
        Remove-PSDrive -Name TempS -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path C:\Windows\System32\Sysprep\Apps4Rent\QBUpdate.ps1 -Confirm:$False -Force | Out-Null
    }
    $ScriptBlock | Out-File C:\Windows\System32\Sysprep\Apps4Rent\QBUpdate.ps1 -Width 4096 -Force 
    Start-Process powershell.exe -ArgumentList "-file C:\Windows\System32\Sysprep\Apps4Rent\QBUpdate.ps1 " -WindowStyle Hidden
  
  
  
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

  function xQBUpdate {
    $max = Get-Date '03:00'
    $min = $max.AddHours(-6)
    $now = Get-Date
    if  ($min -le $now -and $max -ge $now ) {
        ExecuteFunction -RegKeyName QBUpdate -FunctionName $function:QBUpdate -IntervalInMins 180
    }
    
    <#
    $min = Get-Date '22:00'
    $max = Get-Date '03:00'
    $now = Get-Date
    if ($min.TimeOfDay -le $now.TimeOfDay -and $max.TimeOfDay -ge $now.TimeOfDay) {
        ExecuteFunction -RegKeyName QBUpdate -FunctionName $function:QBUpdate -IntervalInMins 240
    }
    #>
}


    xQBUpdate         # This checks if QB updates are available and sent notification. Email Subject: QB updates Available for $QB on: