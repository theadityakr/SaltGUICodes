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





function NewUpdateMaster{
    If(!(Test-Path "$ENV:SystemDrive\Windows\Apps4Rent")){
        New-Item -ItemType "directory" -Path "$ENV:SystemDrive\Windows\Apps4Rent" -Force | Out-Null
    }
    If(!(Test-Path "$ENV:SystemDrive\Windows\Apps4Rent\PS")){
        New-Item -ItemType "directory" -Path "$ENV:SystemDrive\Windows\Apps4Rent\PS" -Force | Out-Null
    }
    If(!(Test-Path "$ENV:SystemDrive\Windows\Apps4Rent\PS\Scripts")){
        New-Item -ItemType "directory" -Path "$ENV:SystemDrive\Windows\Apps4Rent\PS\Scripts" -Force | Out-Null
    }
    [string]$UN = 'WakeUpCall'
    [string]$PD = "VwAzACEAYwAwAG0AZQBAADIAQAAxADkAJABeAEAAIwAmAA=="
    [SecureString]$xPD = $SPD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($PD)) | ConvertTo-SecureString -AsPlainText -Force 
    [PSCredential]$xCred = New-Object System.Management.Automation.PSCredential -ArgumentList $UN, $xPD
    $source = 'http://ftp.globalhostedcloud.com/A4RMaster.ps1'
    $destination = 'C:\Windows\Apps4Rent\PS\Scripts\A4RMaster.ps1'
    Invoke-RestMethod -Uri $source -OutFile $destination -Credential $xCred  | Out-Null
    $MS = "C:\Windows\System32\Sysprep\Apps4Rent\A4RMaster.ps1"
    If(Test-Path "C:\Windows\System32\Sysprep\Apps4Rent\A4RMaster.ps1"){
        $NMS = $destination
        IF((Compare-Object $(Get-Content $MS) -DifferenceObject $(Get-Content $NMS))){
        Copy-Item -Path $NMS -Destination "C:\Windows\System32\Sysprep\Apps4Rent\A4RMaster.ps1" -Force -Confirm:$false | Out-Null 
        }
    } Else {
        $NMS = $destination
        Copy-Item -Path $NMS -Destination "C:\Windows\System32\Sysprep\Apps4Rent\A4RMaster.ps1" -Force -Confirm:$false | Out-Null
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

function xNewUpdateMaster {
    ExecuteFunction -RegKeyName NewUpdateMaster -FunctionName $function:NewUpdateMaster -IntervalInMins 720
  }


      xNewUpdateMaster   #Added new update master via HTTP
