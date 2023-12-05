function OfficeLicenseCheck {
        function OfficeLicenseStatus {
        [CmdletBinding()]
        param (
            [Parameter(Position=0,mandatory=$true)]
            [String]$OSPPPath
        )
        C:\Windows\System32\cscript.exe $OSPPPath.ToString() /dstatus | Out-File $env:temp\actstat.txt
        $ActivationStatus = $($Things = $(Get-Content $env:temp\actstat.txt -raw) `
                            -replace ":"," =" `
                            -split "---------------------------------------" `
                            -notmatch "---Processing--------------------------" `
                            -notmatch "---Exiting-----------------------------"
                        $Things | ForEach-Object {
                        $Props = ConvertFrom-StringData -StringData ($_ -replace '\n-\s+')
                        New-Object psobject -Property $Props  | Select-Object "SKU ID", "LICENSE NAME", "LICENSE DESCRIPTION", "LICENSE STATUS"
                            }
                        )
        $Var = ""
        for ($i=0; $i -le $ActivationStatus.Count-2; $i++) {
            if ($ActivationStatus[$i]."LICENSE STATUS" -eq "---LICENSED---") {
                $Var = "Office Activated"
                }
        
            else {
                $Var = "Office Not Activated"
                }
            }
        Return  $Var, $ActivationStatus
    }

    function SharedLicense {
        Import-module servermanager -ErrorAction SilentlyContinue -Force | Out-Null
        $RDSFeature = (Get-WindowsFeature -name RDS-Licensing).Installed
        If($RDSFeature -like "*True*"){
            $SharedL = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\ -Name SharedComputerLicensing -ErrorAction SilentlyContinue -ErrorVariable ERR | Select-Object -ExpandProperty SharedComputerLicensing
            if($SharedL -notlike '*1*'){
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\' -Name SharedComputerLicensing -Value 1 -Force -Confirm:$false | Out-Null
            }
            iF($ERR -ne $Null){
                New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\' -Name SharedComputerLicensing -Value 1 -PropertyType string -Force -Confirm:$false | Out-Null
            }
        }
    }
    $x64 = 'C:\Program Files\Microsoft Office\Office16\OSPP.VBS'
    $x32 = 'C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS'

    If(Test-Path $x64){
        $Var, $ActivationStatus = OfficeLicenseStatus -OSPPPath $x64
        SharedLicense
    } elseif (Test-Path $x32) {
        $Var, $ActivationStatus = OfficeLicenseStatus -OSPPPath $x32
        SharedLicense
    }
    If($Var -like '*Office Not Activated*'){
        If(Test-Path $x64){
            C:\Windows\System32\cscript.exe $x64.ToString() /act | Out-Null
            $Var, $ActivationStatus = OfficeLicenseStatus -OSPPPath $x64
        } elseif (Test-Path $x32) {
            C:\Windows\System32\cscript.exe $x32.ToString() /act | Out-Null
            $Var, $ActivationStatus = OfficeLicenseStatus -OSPPPath $x32
        }
    }
    If($Var -like '*Office Not Activated*'){
        $HTML = $ActivationStatus | ConvertTo-Html
        $Body =  $VMINFO +  "`r`n"  + $HTML
        $Subject = "Office is Unlicensed on : $Env:ComputerName"
        #Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SMTPServer -BodyAsHtml
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


function xOfficeLicenseCheck {
    ExecuteFunction -RegKeyName OfficeLicenseCheck -FunctionName $function:OfficeLicenseCheck -IntervalInMins 10080
}

    xOfficeLicenseCheck # This checks if Office is unlicenced and try to active. Email Subject: Office is Unlicensed on 