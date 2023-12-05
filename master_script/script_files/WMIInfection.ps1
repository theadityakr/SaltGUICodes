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



function WMIInfection {
$WMIInfection = @()
$WMI = Get-WmiObject -Namespace root\DEFAULT -list *
Foreach($W in $WMI)
{
    If (($W.Properties.name -like '*funs*') -or ($W.Properties.name -like '*mon*') -or ($W.Properties.name -like '*mimi*') -or ($W.Properties.name -like '*ipsu*') -or ($W.Properties.name -like '*i17*'))
    {$WMIInfection += $W.Name}
}
$WMICMDEC = (Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer).Name
$WMIInfection += $WMICMDEC
$WMIEF = (Get-WMIObject -Namespace root\Subscription -Class __EventFilter).Name
$WMIInfection += $WMIEF
$WMIFTCB = (Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding).Name
$WMIInfection += $WMIFTCB
$Body = "Hello, `n WMI Infection Found on $Env:ComputerName `n $WMIInfection `n $VMInfo"
if ($WMIInfection -ne $null)
{
    $Subject = "WMI Infection Found: $Env:ComputerName"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer
    $WMIInfection
    Write-Host "Removing Virus" -ForegroundColor Yellow
    Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Where-Object {$_.name -like '*DSM*'} | Remove-WMIObject -Confirm:$false | Out-Null
    Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Where-Object {$_.name -like '*SCM*'} | Remove-WMIObject -Confirm:$false | Out-Null
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where-Object {$_.name -like '*SCM Event*'} | Remove-WMIObject -Confirm:$false | Out-Null
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where-Object {$_.name -like '*DSM Event*'} | Remove-WMIObject -Confirm:$false | Out-Null
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like '*SCM*'} | Remove-WMIObject -Confirm:$false | Out-Null
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like '*DSM*'} | Remove-WMIObject -Confirm:$false | Out-Null
    foreach ($W in $WMIInfection){
        Get-WmiObject -Namespace root\DEFAULT -List $W -ErrorAction SilentlyContinue | Remove-WMIObject -Confirm:$false | Out-Null
    }
}else {
    Write-Host "No Virus Found" -ForegroundColor Green
}
}

function xWMIInfection {
    ExecuteFunction -RegKeyName WMIInfection -FunctionName $function:WMIInfection -IntervalInMins 5
}


    xWMIInfection    # This removes the WMI infections. Email Subject: WMI Infection Found: