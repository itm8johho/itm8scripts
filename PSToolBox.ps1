### Powershell Toolbox, by John Holst, itm8
# Run from Powershell: IEX ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/itm8johho/itm8scripts/main/PSToolBox.ps1'))
# or create a shotcut
#   Shortcut Name: GIT-PSToolbox
#   Shortcut: Destination: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -ExecutionPolicy Bypass -command "IEX ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/itm8johho/itm8scripts/main/PSToolBox.ps1'))"
#   Shortcut: Start in: %Userprofile%\Desktop
#
# Set of Powershell scripts, that can be used by Consultants
# for getting Customer data, like: Latest Reboot, Ad Users, AD Computers, AD Servers
#
#
#
### Parameter and Shared Functions
Function Verify-ADModuleInstalled {
  If ((Get-Module -Name ActiveDirectory -ListAvailable) -ne $null) {$True} else {If ((Get-WmiObject -class win32_optionalfeature | Where-Object { $_.Name -eq 'RemoteServerAdministrationTools'}) -ne $null) {$True} else {$false}}}
  $DomainQueryEnabled = Verify-ADModuleInstalled; $DomainQueryEnabledInfo = "`n  This function cannot be executed, due to missing Active Directory-functionalities (AD / RSAT) `n"
Function Get-CustomerName {
  # Add this line to Params: $fCustomerName = $(Get-CustomerName)
  ("$($Env:USERDOMAIN)" | %{ If($Entry = Read-Host "  Enter CustomerName ( Default: $_ )"){"$($Entry)_"} Else {"$($_)_"} })
};
Function Get-LogStartTime {
  # Add this line to Params: $fEventLogStartTime = (Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
  Param( $DefaultDays, $DefaultHours,
    $fLastXDays = ("$($DefaultDays)" | %{ If($Entry = Read-Host "  Enter number of days in searchscope (Default: $_ Days)"){$Entry} Else {$_} }),
    $fLastXHours = (%{If ( $fLastXDays -gt 0) {0} Else {"$($DefaultHours)" | %{ If($Entry = Read-Host "  Enter number of hours in searchscope (Default: $_ Hours)"){$Entry} Else {$_} } } })
  );
  ## Script
    $LogStartTime = If ($fLastXDays -gt 0) {$((Get-Date "0:00").adddays(-$($fLastXDays)))} Else {$((Get-Date).AddHours(-$($fLastXHours)).AddMinutes(-(Get-Date).Minute).AddSeconds(-(Get-Date).Second))};
    Return $LogStartTime; # OLD Return [DateTime]::Now.AddDays(-$($fLastXDays)).AddHours(-$($fLastXHours));
};
Function Get-QueryComputers {  ### Get-QueryComputers - Get Domain Servers names
  # Add this line to Params: $fQueryComputers = $(Get-QueryComputers -DefaultComputerSearch "*" -DefaultComputerExcludeList ""), # Enter SearchName(s) / ServerName(s), separated by comma
  Param( $DefaultComputerSearch = "*", $DefaultComputerExcludeList = "",
    $fQueryComputerSearch = ("$($DefaultComputerSearch)" | %{ If($Entry = @(((Read-Host "  Enter SearchName(s), separated by comma ( Default: $_ )").Split(",")).Trim())){$Entry} Else {((($_).Split(",")).Trim())} }),
    $fQueryComputerExcludeList = ("$($DefaultComputerExcludeList)" | %{ If($Entry = @(((Read-Host "  Enter Exclusion ServerName(s), separated by comma ( Default: $_ )").Split(",")).Trim())){$Entry} Else {((($_).Split(",")).Trim())} })
  );
  ## Script
    $fQueryComputers = Foreach ($fComputerSearch in $fQueryComputerSearch) {(Get-ADComputer -Filter 'operatingsystem -like "*server*" -and enabled -eq "true"' -Properties * | where { $fQueryComputerExcludeList -notcontains $_.name} -ErrorAction Continue | where { ($_.name -like $fComputerSearch)} -ErrorAction Continue)};
    $fQueryComputers = $fQueryComputers | Sort Name;
    Return $fQueryComputers;
 };
Function Export-CSVData { Param ( $fFileNameText, $fCustomerName, $fExportData ); ##
  # Add this line to Params: $fFileNameText = "<FILENAME>"    /    $fFileNameText = "<FILENAME>",
  # Add this line to Script: If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $(<EXPORTDATA>) };
  $fFileNameBase = "$($fCustomerName)$(($fFileNameText).Split([IO.Path]::GetInvalidFileNameChars()) -join '_')_($(get-date -f "yyyy-MM-dd_HH.mm"))";
  $fFileName = "$([Environment]::GetFolderPath("Desktop"))\$($fFileNameBase)";
  #$fFileName = "$($env:USERPROFILE)\Desktop\$($fFileNameBase)";
  $fExportData | Export-CSV "$($fFileName).csv" -Delimiter ';' -Encoding UTF8 -NoTypeInformation -ErrorAction SilentlyContinue;
};
Function Show-Title {
  # Add this line to Script: Show-Title "<TITLE>";
  Param ( [string]$Title );
    $host.UI.RawUI.WindowTitle = $Title;
};
Function Show-JobStatus { Param ($fJobNamePrefix)
  # Add this line to Script: Show-JobStatus $fJobNamePrefix;
  DO { IF ((Get-Job -Name "$($fJobNamePrefix)*").count -ge 1) {$fStatus = ((Get-Job -State Completed).count/(Get-Job -Name "$($fJobNamePrefix)*").count) * 100;
    Write-Progress -Activity "Waiting for $((Get-Job -State Running).count) of $((Get-Job -Name "$($fJobNamePrefix)*").count) job(s) to complete..." -Status "$($fStatus) % completed" -PercentComplete $fStatus; }; }
  While ((Get-job -Name "$($fJobNamePrefix)*" | Where State -eq Running));
};
#
## Menu Functions
Function Show-Help {
  Show-Title "$($Title) Help / Information";
  Clear-Host;
  Write-Host "  Help / Information will be updated later";
};
Function Show-Menu {
  param (
    [string]$Title = "PSToolbox"
  );
  Show-Title $Title;
  Clear-Host;
  Write-Host "`n  ================ $Title ================`n";
  #Write-Host "  Press  '0'  for Start SCOM MaintenanceMode for Local Server (Script).";
  Write-Host "  Press  '1'  for Get LatestReboot for Local Computer/Server.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '2'  for Get LatestReboot for Domain Servers."};
  Write-Host "  Press  '3'  for Get LoginLogoff for Local Computer/Server.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '4'  for Get LoginLogoff for Domain Servers."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '5'  for Get AD Users."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '6'  for Get Inactive AD Users / last logon more than eg 90 days."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '7'  for Get Inactive AD Computers / last active more than eg 90 days."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '8'  for Get AD Servers."};
  Write-Host "  Press  '9'  for Get Password Never Expires for User Accounts.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '10'  for Get ITM8 AD Users."};

  Write-Host "  "
  Write-Host "  Press '21' for Get HotFixInstallDates for Local Computer/Server.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '22' for Get HotFixInstallDates for Domain Servers."};
  Write-Host "  Press '23' for Get Installed HotFixes on Local Computer/Server.";
  #Write-Host "  Press '24' for Get - on Local Computer/Server.";
  Write-Host "  Press '25' for Get ExpiredCertificates for Local Server.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '26' for Get ExpiredCertificates for Domain Servers."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '28' for Get IP- and DNS Server-Addresses  for Domain Servers."};

  Write-Host "  "
  Write-Host "  Press '31' for Get FolderPermission for Local Computer/Server.";
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '32' for Get TimeSyncStatus for Domain Servers."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '33' for Get DateTimeStatus for Domain Servers."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '34' for Get FSLogixErrors for Domain Servers."};
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press '35' for Get Get Active admx-/adml- Files for Domain Servers."};
  #Write-Host "  Press '99' for this option.";
  Write-Host "  ";
  Write-Host "   Press 'H'  for Toolbox Help / Information.";
  Write-Host "   Press 'Q'  to quit.";
};
Function ToolboxMenu {
  do {
    Show-Menu
    $selection = Read-Host "`n  Please make a selection"
    switch ($selection){
      "1" { "`n`n  You selected: Get LatestReboot for Local Computer/Server`n"
          $Result = Get-LatestRebootLocal; $Result.LatestBootEventsExtended | FL; $result.LatestBootEvents | FT -Autosize; $result.LatestBootTime | FT -Autosize;
          Pause;};
      "2" { "`n`n  You selected: Get LatestReboot for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-LatestRebootDomain; $Result.LatestBootEvents | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "3" { "`n`n  You selected: Get LoginLogoff for Local Computer/Server`n"
          $Result = Get-LoginLogoffLocal; $Result.LoginLogoff | FT -Autosize;
          Pause;};
      "4" { "`n`n  You selected: Get LoginLogoff for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-LoginLogoffDomain; $Result.LoginLogoff | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "5" { "`n`n  You selected: Get AD Users`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-ADUsers; $Result.count; $Result.ADUsers | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "6" { "`n`n  You selected: Get Inactive AD Users / last logon more than eg 90 days`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-InactiveADUsers; $Result.count; $Result.InactiveADUsers | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "7" { "`n`n  You selected: Get Inactive AD Computers / last active more than eg 90 days`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-InactiveADComputers; $Result.count; $Result.InactiveADComputers | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "8" { "`n`n  You selected: Get AD Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-ADServers; $Result.ADServers | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "9" { "`n`n  You selected: Get Password Never Expires for User Accounts`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-UserPasswordNeverExpires; $Result.count; $Result.UserPasswordNeverExpires | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "10" { "`n`n  You selected: Get ITM8 Users`n"
		  If ($DomainQueryEnabled -eq $True) {$Result = Get-ITM8Users; $Result.count; $Result.ITM8Users | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};

      "21" { "`n`n  You selected: Get HotFixInstallDates for Local Computer/Server`n"
          $Result = Get-HotFixInstallDatesLocal; $Result.HotFixInstallDates | FT -Autosize;
          Pause; };
      "22" { "`n`n  You selected: Get HotFixInstallDates for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-HotFixInstallDatesDomain; $Result.HotFixInstallDates | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "23" { "`n`n  You selected: Get Installed HotFixes on Local Computer/Server`n"
          $Result = Get-HotFixInstalledLocal; $Result.HotFixInstalled | FT -Autosize;
          Pause; };
      "25" { "`n`n  You selected: Get ExpiredCertificates for Local Server`n"
          $Result = Get-ExpiredCertificatesLocal; $Result.ExpiredCertificates | FT -Autosize;
          Pause;};
      "26" { "`n`n  You selected: Get ExpiredCertificates for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-ExpiredCertificatesDomain; $Result.ExpiredCertificates | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};

      "28" { "`n`n  You selected: Get IP- and DNS-Server-Addresses for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-NetAdapterInfoDomain; $Result.NetAdapterInfo | FT -Autosize;;} ELSE {$DomainQueryEnabledInfo}
          Pause;};

      "31" { "`n`n  You selected: Get FolderPermission for Local Computer/Server`n"
		  $Result = Get-FolderPermissionLocal; $Result.FolderPermission | FT -Autosize; $Result.FolderPermission_Level_01_02 | FT -Autosize;
          Pause;};
      "32" { "`n`n  You selected: Get TimeSync Status for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-TimeSyncStatusDomain; $Result.TimeSyncStatus | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "33" { "`n`n  You selected: Get DateTimeStatus for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-DateTimeStatusDomain; $Result.DateTimeStatus | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "34" { "`n`n  You selected: Get FSLogixErrors for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-FSLogixErrorsDomain; $Result.FSLogixErrors | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "35" { "`n`n  You selected: Get Active admx-/adml- Files for Domain Servers`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-ActiveADMxFiles;
              $Result.admxResult | FT -Autosize; $Result.admxFilesUnique | FT -Autosize; $Result.admxCounts; ## ADMX-Files Results
              $Result.admlResult | FT -Autosize; $Result.admlFilesUnique | FT -Autosize; $Result.admlCounts; ## ADML-Files Results
              $Result.admxadmlFiles | FT -Autosize; ## ADMX+ADML-Files Results
              $Result.admxCounts; $Result.admlCounts; ## Output Overview
          } ELSE {$DomainQueryEnabledInfo}
          Pause;};
      "99" { "`n`n  You selected: Test option #99`n"
          Sleep 10;
      };
      "0" { "`n`n  You selected: Start SCOM MaintenanceMode for Local Server`n"
        #Start-SCOMMaintenanceMode;
        Pause;};
      "H" { "`n`n  You selected: Help / Information option `n"
        Show-Help;
        Pause;};
    }; # End Switch
  } until (($selection -eq "q") -or ($selection -eq "0"));
};
## End Start Menu
### Functions
Function Get-LatestRebootLocal { ### Get-LatestReboot - Get Latest Reboot / Restart / Shutdown for logged on server
  Param(
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
	$fEventLogStartTime = (Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    $fFileNameText = "Get-LatestReboot_$($ENV:Computername)"
  );
  ## Script
    Show-Title "Get latest Shutdown / Restart / Reboot for Local Server - Events After: $($fEventLogStartTime)";
    $fLatestBootTime = Get-WmiObject win32_operatingsystem | select csname, @{LABEL="LastBootUpTime";EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}};
    $fResult = Get-EventLog -LogName System -After $fEventLogStartTime | Where-Object {($_.EventID -eq 1074) -or ($_.EventID -eq 6008) -or ($_.EventID -eq 41)};
	IF (!($fResult)){$fResult = [pscustomobject]@{MachineName = $($Env:COMPUTERNAME);TimeGenerated = ""; UserName = "$($($Env:COMPUTERNAME)) is not rebooted in the query periode" }};
  ## Output
    # $fResult | Select MachineName, TimeGenerated, UserName, Message | fl; $fResult | Select MachineName, TimeGenerated, UserName | ft -Autosize; $fLatestBootTime;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName, Message) };
  ## Return
    [hashtable]$Return = @{};
    $Return.LatestBootEventsExtended = $fResult | Select MachineName, TimeGenerated, UserName, Message;
    $Return.LatestBootEvents = $fResult | Select MachineName, TimeGenerated, UserName;
    $Return.LatestBootTime = $fLatestBootTime;
    Return $Return
};
Function Get-LatestRebootDomain { ### Get-LatestReboot - Get Latest Reboot / Restart / Shutdown for multiple Domain servers
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fEventLogStartTime = $(Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    #$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fExport = "Yes",
    $fExportExtended = ("Yes" | %{ If($Entry = Read-Host "  Export Standard & Extended(message included) result to file - ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fJobNamePrefix = "LatestReboot_",
    $fFileNameText = "Servers_Get-LatestReboot"
  );
  ## Script
    Show-Title "Get latest Shutdown / Restart / Reboot for multiple Domain Servers - Events After: $($fEventLogStartTime)";
    Foreach ($fQueryComputer in $fQueryComputers.name) { # Get $fQueryComputers-Values like .Name, .DNSHostName, or add them to variables in the scriptblocks/functions
      Write-Host "Querying Server: $($fQueryComputer)";
      $fBlock01 = {$fBlockResult = Get-EventLog -LogName System -After $Using:fEventLogStartTime | Where-Object {($_.EventID -eq 1074) -or ($_.EventID -eq 6008) -or ($_.EventID -eq 41) }
        IF (!($fBlockResult)){$fBlockResult = [pscustomobject]@{MachineName = $($Env:COMPUTERNAME);TimeGenerated = ""; UserName = "$($($Env:COMPUTERNAME)) is not rebooted in the query periode" }};
        $fBlockResult;
      };
      $fLocalBlock01 = {$fBlockResult = Get-EventLog -LogName System -After $fEventLogStartTime | Where-Object {($_.EventID -eq 1074) -or ($_.EventID -eq 6008) -or ($_.EventID -eq 41) }
        IF (!($fBlockResult)){$fBlockResult = [pscustomobject]@{MachineName = $($Env:COMPUTERNAME);TimeGenerated = ""; UserName = "$($($Env:COMPUTERNAME)) is not rebooted in the query periode" }};
        $fBlockResult;
      };
      IF ($fQueryComputer -eq $Env:COMPUTERNAME) {
        $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01;
      } ELSE {
        $fJobResult = Invoke-Command -scriptblock $fBlock01 -ComputerName $fQueryComputer -JobName "$($fJobNamePrefix)$($fQueryComputer)" -ThrottleLimit 16 -AsJob
      };
    };
    Write-Host "  Waiting for jobs to complete... `n";
    Show-JobStatus $fJobNamePrefix;
    $fResult = Foreach ($fJob in (Get-Job -Name "$($fJobNamePrefix)*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job;
    $fResult = $fResult + $fLocalHostResult;
  ## Output
    #$fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName) };
    If (($fExportExtended -eq "Y") -or ($fExportExtended -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_Extended" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName, Message) };
  ## Return
    [hashtable]$Return = @{};
    $Return.LatestBootEvents = $fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName;
    Return $Return;
};
Function Get-LoginLogoffLocal { ## Get-LoginLogoff from Logged On for Local Computer/Server
  Param(
    $fEventLogStartTime = $(Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Get-LatestLoginLogoff_$($ENV:Computername)"
  );
  ## Default Variables
    $fUserProperty = @{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}}
    $fTypeProperty = @{n="Action";e={if($_.EventID -eq 7001) {"Logon"} elseif ($_.EventID -eq 7002){"Logoff"} else {"other"}}}
    $fTimeProperty = @{n="Time";e={$_.TimeGenerated}}
    $fMachineNameProperty = @{n="MachineName";e={$_.MachineName}}
  ## Script
    Show-Title "Get latest Login / Logoff for Local Computer/Server - Events After: $($fEventLogStartTime)";
    Write-Host "Querying Computer: $($ENV:Computername)"
    $fResult = Get-EventLog System -Source Microsoft-Windows-Winlogon -after $fEventLogStartTime | select $fUserProperty,$fTypeProperty,$fTimeProperty,$fMachineNameProperty
  ## Output
    #$fResult | sort User, Time | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort User, Time) };
  ## Return
    [hashtable]$Return = @{};
    $Return.LoginLogoff = $fResult | sort User, Time;
    Return $Return;
};
Function Get-LoginLogoffDomain { ## Get-LoginLogoffDomain (Remote) from Event Log: Microsoft-Windows-Winlogon
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fEventLogStartTime = $(Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Servers_Get-LatestLoginLogoff"
  );
  ## Default Variables
    $fUserProperty = @{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}};
    $fTypeProperty = @{n="Action";e={if($_.EventID -eq 7001) {"Logon"} elseif ($_.EventID -eq 7002){"Logoff"} else {"other"}}};
    $fTimeProperty = @{n="Time";e={$_.TimeGenerated}};
    $fMachineNameProperty = @{n="MachineName";e={$_.MachineName}};
  ## Script
    Show-Title "Get latest Login / Logoff  for multiple Domain Servers - Events After: $($fEventLogStartTime)";
    $fResult = foreach ($fComputer in $fQueryComputers.name) { # Get Values like .Name, .DNSHostName
      Write-Host "Querying Computer: $($fComputer)"
      Get-EventLog System -Source Microsoft-Windows-Winlogon -ComputerName $fComputer -after $fEventLogStartTime | Select $fUserProperty,$fTypeProperty,$fTimeProperty,$fMachineNameProperty;
    };
  ## Output
    #$fResult | sort User, Time | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort User, Time) };
  ## Return
    [hashtable]$Return = @{};
    $Return.LoginLogoff = $fResult | sort User, Time;
    Return $Return;
};
Function Get-ADUsers {## Get AD Users
  Param(
    $fCustomerName = $(Get-CustomerName),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "ADUsers"
  );
  ## Script
    Show-Title "Get AD Users";
    $fResult = Get-Aduser -Filter * -Properties *  | Sort-Object -Property samaccountname | Select CN, DisplayName, Samaccountname,@{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled, LockedOut, PasswordNeverExpires, @{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}}, Description;
  ## Output
    #$fResult | Sort DisplayName | Select CN, DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ADUsers = $fResult | Sort DisplayName | Select CN, DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description;
    Return $Return;
};
Function Get-InactiveADUsers {## Get inactive AD Users / Latest Logon more than eg 90 days
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fDaysInactive = ("90" | %{ If($Entry = Read-Host "  Enter number of inactive days (Default: $_ Days)"){$Entry} Else {$_} }),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Inactive_ADUsers_last_$($fDaysInactive)_days"
  );
  ## Script
    Show-Title "Get AD Users Latest Logon / inactive more than $($fDaysInactive) days";
	$fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-Aduser -Filter {(LastLogonTimeStamp -lt $fDaysInactiveTimestamp) -or (LastLogonTimeStamp -notlike "*")} -Properties *  | Sort-Object -Property samaccountname | Select CN,DisplayName,Samaccountname,@{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}},Enabled,LockedOut, PasswordNeverExpires,@{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}},Description;
  ## Output
    #$fResult | Sort DisplayName | Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description) };
  ## Return
    [hashtable]$Return = @{};
    $Return.InactiveADUsers = $fResult | Sort DisplayName | Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
    Return $Return;
};
Function Get-InactiveADComputers {## Get inactive AD Computers / Latest Logon more than eg 90 days
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fDaysInactive = ("90" | %{ If($Entry = Read-Host "  Enter number of inactive days (Default: $_ Days)"){$Entry} Else {$_} }),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Inactive_ADComputers_last_$($fDaysInactive)_days"
  );
  ## Script
    Show-Title "Get AD Computers Latest Logon / inactive more than $($fDaysInactive) days";
	$fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-ADComputer -Filter {LastLogonDate -lt $fDaysInactiveTimestamp } -Properties CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName | Sort-Object -Property CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Output
    #$fResult | Sort CN | Select CN, LastLogonDate, OperatingSystem, CanonicalName;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.InactiveADComputers = $fResult | Sort CN | Select CN, LastLogonDate, OperatingSystem, Enabled, CanonicalName;
    Return $Return;
};
Function Get-ADServers {## Get AD Servers
  Param(
    $fCustomerName = $(Get-CustomerName),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "ADServers"
  );
  ## Script
    Show-Title "Get AD Server";
    $fResult = Get-ADComputer -Filter {(operatingsystem -like "*server*") } -Properties CN, LastLogonDate, OperatingSystem, CanonicalName | Sort-Object -Property CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Output
    #$fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ADServers = $fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
    Return $Return;
};
Function Get-UserPasswordNeverExpires {## Get Password Never Expires for User Accounts
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "UserPasswordNeverExpires"
  );
  ## Script
    Show-Title "Get Password Never Expires for User Accounts";
    $fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-ADUser -Filter * -Properties Name, LockedOut, PasswordNeverExpires, pwdlastSet | where { $_.passwordNeverExpires -eq $true } | Sort Name | Select-Object Name, SamAccountName, LockedOut, @{n="PwdNeverExpires";e={$_.PasswordNeverExpires}}, @{n="PwdLastSet";e={[datetime]::FromFileTime($_."PwdLastSet").ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled;
  ## Output
    #$fResult;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult) };
  ## Return
    [hashtable]$Return = @{};
    $Return.UserPasswordNeverExpires = $fResult;
    Return $Return;
};
Function Get-ITM8Users {## Get ITM8 AD Users
  Param(
    $fCustomerName = $(Get-CustomerName),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "ITM8_Users"
  );
  ## Script
    Show-Title "Get ITM8 AD Users";
    $fResult = Get-ADUser -Filter * -Properties * | ? { ($_.DistinguishedName -Like "*OU=ITM8*") -or ($_.Description -like "*ITM8*") -or ($_.Samaccountname -like "*ITM8*") -or ($_.DisplayName -like "*ITM8*") -or ($_.DistinguishedName -Like "*OU=Progressive*") -or ($_.Description -like "*Progressive*") -or ($_.Samaccountname -like "*ProAdmin*") -or ($_.DisplayName -like "*ProAdmin*") -or ($_.Samaccountname -like "*PIT-Support*") -or ($_.DisplayName -like "*PIT-Support*") -or ($_.Samaccountname -like "*DTAdmin*") -or ($_.DisplayName -like "*DTAdmin*")} | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, @{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled, LockedOut, PasswordNeverExpires, @{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}}, Description, DistinguishedName;
  ## Output
    #$fResult.count; $fResult | Sort Enabled, DisplayName | ft ;# Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description, DistinguishedName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ITM8Users = $fResult | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description, DistinguishedName;
    Return $Return;
};
Function Get-HotFixInstallDatesLocal { ### Get-HotFixInstallDates for Local Computer/Server
  Param(
    $fHotfixInstallDates = ("3" | %{ If($Entry = Read-Host "  Enter number of Hotfix-install dates per Computer (Default: $_ Install Dates)"){$Entry} Else {$_} }),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Get-HotFixInstallDates_$($ENV:Computername)"
    );
  ## Script
    Show-Title "Get latest $($fHotfixInstallDates) HotFix Install Dates Local Computer/Server";
    $fResult = Get-Hotfix | sort InstalledOn -Descending -Unique -ErrorAction SilentlyContinue | Select -First $fHotfixInstallDates | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
    $fResult | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$((Get-ComputerInfo).WindowsProductName)";
    $fResult | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$((Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -notlike '127.0.0.1' }).IPAddress)";
  ## Output
    #$fResult | sort MachineName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
  ## Return
    [hashtable]$Return = @{};
    $Return.HotFixInstallDates = $fResult | sort MachineName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address;
    Return $Return;
};
Function Get-HotFixInstallDatesDomain { ### Get-HotFixInstallDates for multiple Domain servers
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fHotfixInstallDates = ("3" | %{ If($Entry = Read-Host "  Enter number of Hotfix-install dates per Computer (Default: $_ Install Dates)"){$Entry} Else {$_} }),
    #$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fExport = "Yes",
    $fFileNameText = "Servers_Get-HotFixInstallDates"
    );
  ## Script
    Show-Title "Get latest $($fHotfixInstallDates) HotFix Install Dates multiple Domain Servers";
    $fResult = @(); $fResult = Foreach ($fQueryComputer in $fQueryComputers) {
      Write-Host "  Querying Server: $($fQueryComputer.Name)";
      IF ($fQueryComputer.Name -eq $Env:COMPUTERNAME) {
        $fInstalledHotfixes = Get-Hotfix | sort InstalledOn -Descending -Unique -ErrorAction SilentlyContinue | Select -First $fHotfixInstallDates | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
        $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$((Get-ComputerInfo).WindowsProductName)";
        $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$((Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -notlike '127.0.0.1' }).IPAddress)";
        $fInstalledHotfixes; 
      } Else {
        try {
          $fInstalledHotfixes = Get-Hotfix -ComputerName $fQueryComputer.Name | sort InstalledOn -Descending -Unique -ErrorAction SilentlyContinue | Select -First $fHotfixInstallDates | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
          $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$($fQueryComputer.OperatingSystem)";
          $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$($fQueryComputer.IPv4Address)";
          $fInstalledHotfixes; 
        } catch {
          Write-Host "      An error occurred within the Get-Hotfix command:"
          Write-Host "      $($_.ScriptStackTrace)`n"
          Write-Host "      Querying Server: $($fQueryComputer.Name) with Invoked Get-Hotfix command: "
          try {
            IF (Test-Connection -computername $fQueryComputer.Name -Quiet -Count 1) {
              $fInstalledHotfixes = Invoke-Command -scriptblock { Get-Hotfix | sort InstalledOn -Descending -Unique -ErrorAction SilentlyContinue | Select -First $USING:fHotfixInstallDates | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;} -computername $fQueryComputer.Name;
              $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$($fQueryComputer.OperatingSystem)";
              $fInstalledHotfixes | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$($fQueryComputer.IPv4Address)";
              $fInstalledHotfixes; 
			} Else {
              $fInstalledHotfixes = [pscustomobject][Ordered]@{
                "PSComputerName" = "$($fQueryComputer.Name)";
                "InstalledOn" = "";
                "InstalledBy" = "";
                "HotFixID" = "";
                "Description" = "";
                "OperatingSystem" = "$($fQueryComputer.OperatingSystem)";
                "IPv4Address" = "$($fQueryComputer.IPv4Address)"};
              $fInstalledHotfixes; 
            };				
          } catch {
            Write-Host "      An error occurred within the Invoked Get-Hotfix command:"
            Write-Host "      $($_.ScriptStackTrace)`n"
            $fInstalledHotfixes = [pscustomobject][Ordered]@{
              "PSComputerName" = "$($fQueryComputer.Name)";
              "InstalledOn" = "";
              "InstalledBy" = "";
              "Description" = "";
              "HotFixID" = "";
              "OperatingSystem" = "$($fQueryComputer.OperatingSystem)";
              "IPv4Address" = "$($fQueryComputer.IPv4Address)"};
            $fInstalledHotfixes; 
    }}}};
  ## Output
    #$fResult | sort PSComputerName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort PSComputerName | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
  ## Return
    [hashtable]$Return = @{};
    $Return.HotFixInstallDates = $fResult | sort PSComputerName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address;
    Return $Return;
};
Function Get-HotFixInstalledLocal { ### Get-HotFixInstalled on Local Computer/Server
  Param(
    $fHotfixInstallDays = ("90" | %{ If($Entry = Read-Host "  Enter number of days for Installed Hotfixes on Local Computer/Server (Default: $_ Install Days)"){$Entry} Else {$_} }),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Get-HotFixInstalled_$($ENV:Computername)"
    );
  ## Script
    Show-Title "Get Installed HotFixes for latest $($fHotfixInstallDays) days on Local Computer/Server";
    $fResult = Get-Hotfix | sort InstalledOn -Descending -ErrorAction SilentlyContinue | ? { $_.InstalledOn -gt $((Get-Date "0:00").adddays(-$($fHotfixInstallDays)))} | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
    $fResult | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$((Get-ComputerInfo).WindowsProductName)";
    $fResult | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$((Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -notlike '127.0.0.1' }).IPAddress)";
  ## Output
    #$fResult | sort InstalledOn, HotFixID -Descending | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
  ## Return
    [hashtable]$Return = @{};
    $Return.HotFixInstalled = $fResult | sort InstalledOn, HotFixID -Descending | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address;
    Return $Return;
  ## $Result = Get-HotFixInstalledLocal; $Result.HotFixInstalled | FT -Autosize;
};
Function Get-ExpiredCertificatesLocal {## Get-ExpiredCertificates
  Param(
    $fCertSearch = ("*" | %{ If($Entry = @(((Read-Host "  Enter Certificate SearchName(s), separated by comma ( Default: $_ )").Split(",")).Trim())){$Entry} Else {$_} }),
    $fExpiresBeforeDays = ("90" | %{ If($Entry = Read-Host "  Enter number of days before expire (Default: $_ Days)"){$Entry} Else {$_} }),
	$fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Get-Expired_Certificates"
  );
  ## Script
    Show-Title "Get Certificates expired or expire within next $($fExpiresBeforeDays) days on Local Server";
	$fExpiresBefore = [DateTime]::Now.AddDays($($fExpiresBeforeDays));
    $fResult = Get-ChildItem -path "cert:LocalMachine\my" -Recurse | ? {$_.NotAfter -lt "$fExpiresBefore"} | ? {($_.Subject -like $fCertSearch) -or ($_.FriendlyName -like $fCertSearch)} | Select @{Name="ServerName";Expression={$env:COMPUTERNAME}}, @{Name="Expires";Expression={($_.NotAfter).ToString("yyyy-MM-dd HH:mm:ss")}}, FriendlyName, Subject, @{Name="ParentPath";Expression={$_.PSParentPath.Replace("Microsoft.PowerShell.Security\Certificate::","")}}, Issuer, Thumbprint;
	  ## Output
    #$fResult | Sort Expires, FriendlyName | Select Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult |  sort Expires, FriendlyName | Select ServerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ExpiredCertificates = $fResult | Sort ServerName, Expires, FriendlyName | Select ServerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint;
    Return $Return;
};
Function Get-ExpiredCertificatesDomain {## Get-Expired_Certificates
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fCertSearch = ("*" | %{ If($Entry = @(((Read-Host "  Enter Certificate SearchName(s), separated by comma ( Default: $_ )").Split(",")).Trim())){$Entry} Else {$_} }),
    $fQueryComputers = $(Get-QueryComputers),
    $fExpiresBeforeDays = ("90" | %{ If($Entry = Read-Host "  Enter number of days before expire (Default: $_ Days)"){$Entry} Else {$_} }),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fJobNamePrefix = "ExpiredCertificates_",
    $fFileNameText = "Servers_Get-Expired_Certificates"
  );
  ## Script
    Show-Title "Get Certificates expired or expire within next $($fExpiresBeforeDays) days on multiple Domain Servers";
    $fExpiresBefore = [DateTime]::Now.AddDays($($fExpiresBeforeDays));
    $fResult = Foreach ($fQueryComputer in $fQueryComputers.name) { # Get $fQueryComputers-Values like .Name, .DNSHostName, or add them to variables in the scriptblocks/functions
      Write-Host "Querying Server: $($fQueryComputer)";
      $fBlock01 = {Get-ChildItem -path "cert:LocalMachine\my" -Recurse | ? {$_.NotAfter -lt "$Using:fExpiresBefore"} | ? {($_.Subject -like $Using:fCertSearch) -or ($_.FriendlyName -like $Using:fCertSearch)} | Select @{Name="Expires";Expression={$_.NotAfter}}, FriendlyName, Subject, @{Name="ParentPath";Expression={$_.PSParentPath.Replace("Microsoft.PowerShell.Security\Certificate::","")}}, Issuer, Thumbprint;};
      $fLocalBlock01 = {Get-ChildItem -path "cert:LocalMachine\my" -Recurse | ? {$_.NotAfter -lt "$fExpiresBefore"} | ? {($_.Subject -like $fCertSearch) -or ($_.FriendlyName -like $fCertSearch)} | Select @{Name="Expires";Expression={($_.NotAfter).ToString("yyyy-MM-dd HH:mm:ss")}}, FriendlyName, Subject, @{Name="ParentPath";Expression={$_.PSParentPath.Replace("Microsoft.PowerShell.Security\Certificate::","")}}, Issuer, Thumbprint;};
      IF ($fQueryComputer -eq $Env:COMPUTERNAME) {
        $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01;
      } ELSE {
        $JobResult = Invoke-Command -scriptblock $fBlock01 -ComputerName $fQueryComputer -JobName "$($fJobNamePrefix)$($fQueryComputer)" -ThrottleLimit 16 -AsJob
      };
    };
    Write-Host "  Waiting for jobs to complete... `n";
    Show-JobStatus $fJobNamePrefix;
    $fResult = Foreach ($fJob in (Get-Job -Name "$($fJobNamePrefix)*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job;
    $fResult = $fResult + $fLocalHostResult;
  ## Output
    #$fResult | Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult |  Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ExpiredCertificates = $fResult |  Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint;
    Return $Return;
};
Function Get-NetAdapterInfo {
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fJobNamePrefix = "NetAdapterInfo_",
    $fFileNameText = "NetAdapterInfo"
  );
  ## Script
    $fBlock01 = { $NetAdapter = Get-NetAdapter -Name *
      $fIPAdresses = $NetAdapter | Get-NetIPAddress -AddressFamily IPv4 | Select InterfaceAlias, IPAddress, PrefixOrigin;
      $fDNSServers = $NetAdapter | Get-DnsClientServerAddress -AddressFamily IPV4 | select -Property InterfaceAlias, ServerAddresses;
      $fNetAdapterInfo = [pscustomobject][Ordered]@{
        "ComputerName" = $ENV:ComputerName;
        "DHCP" = $fIPAdresses.PrefixOrigin
        "IPAdresses" = $fIPAdresses.IPAddress;
        "DNSServers" = $fDNSServers.ServerAddresses;
        "InterfaceAlias" = $fIPAdresses.InterfaceAlias;
      };
      $fNetAdapterInfo
    };
    $fLocalBlock01 = { $NetAdapter = Get-NetAdapter -Name *
      $fIPAdresses = $NetAdapter | Get-NetIPAddress -AddressFamily IPv4  -ErrorAction SilentlyContinue | Select InterfaceAlias, IPAddress, PrefixOrigin;
      $fDNSServers = $NetAdapter | Get-DnsClientServerAddress -AddressFamily IPV4  -ErrorAction SilentlyContinue | select -Property InterfaceAlias, ServerAddresses;
      $fNetAdapterInfo = [pscustomobject][Ordered]@{
        "ComputerName" = $ENV:ComputerName;
        "DHCP" = $fIPAdresses.PrefixOrigin;
        "IPAdresses" = $fIPAdresses.IPAddress;
        "DNSServers" = $fDNSServers.ServerAddresses;
        "InterfaceAlias" = $fIPAdresses.InterfaceAlias;
      };
      $fNetAdapterInfo;
    };
    ForEach ($fQueryComputer in $fQueryComputers) {
      Write-Host "Querying Server: $($fQueryComputer.name)";
      IF ($fQueryComputer -eq $Env:COMPUTERNAME) {
        $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01;
      } ELSE {
        $fJobResult = Invoke-Command -ComputerName $fQueryComputer.name -ScriptBlock $fBlock01 -JobName "$($fJobNamePrefix)$($fQueryComputer.name)" -ThrottleLimit 16 -AsJob
      };
    };
      Write-Host "  Waiting for jobs to complete... `n";
      Show-JobStatus $fJobNamePrefix;
      $fResult = @(); $fResult = Foreach ($fJob in (Get-Job -Name "$($fJobNamePrefix)*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job; Write-Host $(Get-Job |ft -AutoSize  | out-string); Get-Job -State Failed | Remove-Job;
      $fResult = $fResult + $fLocalHostResult; $fResult = $fResult | Sort DHCP, ComputerName, InterfaceAlias | Select ComputerName, DHCP, IPAdresses, DNSServers, InterfaceAlias;
 ## Output
    #$fResult | FT -Autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult;)};
   ## Return
    [hashtable]$Return = @{}; 
    $Return.NetAdapterInfo = $fResult;
    Return $Return;
};
  ForEach ($fQueryComputer in $fQueryComputers) {
    Write-Host "Querying Server: $($fQueryComputer.name)";
    IF ($fQueryComputer -eq $Env:COMPUTERNAME) {
      $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01;
    } ELSE {
      $fJobResult = Invoke-Command -ComputerName $fQueryComputer.name -ScriptBlock $fBlock01 -JobName "$($fJobNamePrefix)$($fQueryComputer.name)" -ThrottleLimit 16 -AsJob
    };
  };
Function Get-TimeSyncStatusDomain {## Get TimeSync Status (Registry) - need an AD Server or Server with RSAT
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fJobNamePrefix = "TimeSyncStatus_",
    $fFileNameText = "TimeSyncStatus"
  );
  ## Script
    Show-Title "Get TimeSync Status (Registry)";
    $NTP_reg = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
    $fBlock01 = {
      $TimeServiceStatus = Get-Service W32Time | Select DisplayName, Status
      $NTPConfigStatus = Get-ItemProperty $USING:NTP_reg | Select NtpServer, Type
      $NTPStatusResult = [pscustomobject]@{
        "Servername" = "$($Env:COMPUTERNAME)"
        "NtpServer" = $NTPConfigStatus.NtpServer
        "NTPType" = $NTPConfigStatus.Type
        "TimeServiceStatus" = $TimeServiceStatus.Status};
      $NTPStatusResult; 
    };
    $fLocalBlock01 = {
      $TimeServiceStatus = Get-Service W32Time | Select DisplayName, Status
      $NTPConfigStatus = Get-ItemProperty $NTP_reg | Select NtpServer, Type
      $NTPStatusResult = [pscustomobject]@{
        "Servername" = "$($Env:COMPUTERNAME)"
        "NtpServer" = $NTPConfigStatus.NtpServer
        "NTPType" = $NTPConfigStatus.Type
        "TimeServiceStatus" = $TimeServiceStatus.Status};
      $NTPStatusResult; 
    };
    $fResult = Foreach ($fQueryComputer in $fQueryComputers) {
      Write-Host "Querying Server: $($fQueryComputer.name)";
      IF ($fQueryComputer.name -eq $Env:COMPUTERNAME) {
        $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01;
      } ELSE {
        $JobResult = Invoke-Command -ComputerName $fQueryComputer.name -ScriptBlock $fBlock01 -JobName "$($fJobNamePrefix)$($fQueryComputer)" -ThrottleLimit 16 -AsJob
	  };
    };
    Write-Host "  Waiting for jobs to complete... `n";
    Show-JobStatus $fJobNamePrefix;
    $fResult = Foreach ($fJob in (Get-Job -Name "$($fJobNamePrefix)*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job;
    $fResult = $fResult + $fLocalHostResult;
 ## Output
    #$fResult | Sort Servername | FT Servername, NTPServer, NTPType, TimeServiceStatus;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Servername | Select Servername, NTPServer, NTPType, TimeServiceStatus) };
  ## Return
    [hashtable]$Return = @{};
    $Return.TimeSyncStatus = $fResult | Sort Servername | FT Servername, NTPServer, NTPType, TimeServiceStatus;
    Return $Return;
};
Function Get-DateTimeStatusDomain {## Get Date & Time Status - need an AD Server or Server with RSAT
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fJobNamePrefix = "DateTimeStatus_",
    $fFileNameText = "DateTimeStatus"
	);
  ## Script
    Show-Title "Get Date and Time status from Domain Servers";
    Foreach ($fQueryComputer in $fQueryComputers.name) { # Get $fQueryComputers-Values like .Name, .DNSHostName, or add them to variables in the scriptblocks/functions
      Write-Host "Querying Server: $($fQueryComputer)";
      $fBlock01 = {
        $fInternetTime = Try {(Invoke-RestMethod -Uri "https://timeapi.io/api/Time/current/zone?timeZone=Europe/Copenhagen")} Catch {"Not Available"};
        $fLocalTime = (Get-Date -f "yyyy-MM-dd HH:mm:ss");
        New-Object psobject -Property ([ordered]@{
          InternetTime = If ($fInternetTime -ne "Not Available") {$fInternetTime.dateTime.replace("T"," ").split(".")[0]} Else {$fInternetTime};
          LocalTime = $fLocalTime;
          LocalNTPServer = (w32tm /query /source);
          LocalCulture = Get-Culture;
          LocalTimeZone = Try {Get-TimeZone} Catch {(Get-WMIObject -Class Win32_TimeZone).Caption};
          InternetTimeZone = If ($fInternetTime -ne "Not Available") {$fInternetTime.timeZone} Else {$fInternetTime};
        });
      };
      $fLocalBlock01 = {
        $fInternetTime = Try {(Invoke-RestMethod -Uri "https://timeapi.io/api/Time/current/zone?timeZone=Europe/Copenhagen")} Catch {"Not Available"};
        $fLocalTime = (Get-Date -f "yyyy-MM-dd HH:mm:ss");
        New-Object psobject -Property ([ordered]@{
          PSComputerName = $Env:COMPUTERNAME;
          InternetTime = If ($fInternetTime -ne "Not Available") {$fInternetTime.dateTime.replace("T"," ").split(".")[0]} Else {$fInternetTime};
          LocalTime = $fLocalTime;
          LocalNTPServer = (w32tm /query /source);
          LocalCulture = Get-Culture;
          LocalTimeZone = Try {Get-TimeZone} Catch {(Get-WMIObject -Class Win32_TimeZone).Caption};
          InternetTimeZone = If ($fInternetTime -ne "Not Available") {$fInternetTime.timeZone} Else {$fInternetTime};
        });
      };
      IF ($fQueryComputer -eq $Env:COMPUTERNAME) {
        $fLocalHostResult = Invoke-Command -scriptblock $fLocalBlock01 
      } ELSE {
        $JobResult = Invoke-Command -scriptblock $fBlock01 -ComputerName $fQueryComputer -JobName "$($fJobNamePrefix)$($fQueryComputer)" -ThrottleLimit 16 -AsJob
      };
    };
    Write-Host "  Waiting for jobs to complete... `n";
	Show-JobStatus $fJobNamePrefix;
	$fResult = Foreach ($fJob in (Get-Job -Name "$($fJobNamePrefix)*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job;
    $fResult = $fResult + $fLocalHostResult;
  ## Output
    #$fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone) };
  ## Return
    [hashtable]$Return = @{};
    $Return.DateTimeStatus = $fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone;
    Return $Return;
};
Function Get-FSLogixErrorsDomain {## Get FSLogix Errors - need an AD Server or Server with RSAT
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fLogDays = ("7" | %{ If($Entry = Read-Host "  Enter number of days in searchscope (Default: $_ Days)"){$Entry} Else {$_} }),
    $fFileNameText = "FSLogixErrors",
    $fErrorCodes1 = @("00000079", "0000001f", "00000020"),
    $fErrorCodes2 = @("00000079", "0000001f"),
    $fErrorCodeList = "  Internal Error Code Description:
  00000005 Access is denied
  00000020 Operation 'OpenVirtualDisk' failed / Failed to open virtual disk / The process cannot access the file because it is being used by another process.
  00000091 The directory is not empty
  00000079 Failed to attach VHD / LoadProfile failed / AttachVirtualDisk error for user
  0000001f Error (A device attached to the system is not functioning.)
  00000091 Error removing directory (The directory is not empty.)
  000003f8 Restoring registry key (An I/O operation initiated by the registry failed unrecoverable...)
  0000078f FindFile failed for path: / LoadProfile failed.
  00000490 Failed to remove RECYCLE.BIN redirect (Element not found.)
  00001771 Failed to restore credentials. Unable to decrypt value from BlobDpApi attribute (The specified file could not be decrypted.)
  0000a418 Unable to get the supported size or compact the disk, Message: Cannot shrink a partition containing a volume with errors
  80070003 Failed to save installed AppxPackages (The system cannot find the path specified.)
  80070490 Error removing Rule (Element not found)"
  );
  ## Script
    Show-Title "Get FSLogix Errors for past $($fLogDays) days";
    $fExportAllErrors = "$FALSE" ; # Select "$TRUE" or "$FALSE"
    ## ErrorCode Selection
      Clear-Host;
      Write-Host "`n  ================ Select FSLogix ErrorCodes ================`n";
      Write-Host "  Press '1'  for FSLogix ErrorCodes $($fErrorCodes1).";
      Write-Host "  Press '2'  for FSLogix ErrorCodes $($fErrorCodes2).";
      Write-Host "  Press 'M'  for entering FSLogix ErrorCodes manually.";
      Write-Host "  Press 'A'  for All FSLogix ErrorCodes.";
    $ErrorCodeSelection = Read-Host "`n  Please make a selection"
    switch ($ErrorCodeSelection){
      "1" {$fErrorCodes = $fErrorCodes1;} # @("ERROR:", "WARN:") @("00000079", "0000001f", "00000020")
      "2" {$fErrorCodes = $fErrorCodes2;} # @("ERROR:", "WARN:") @("00000079", "0000001f");} 
      "m" {$fErrorCodes = ($Entry = @(((Read-Host "  Enter FXLogix ErrorCode(s), to search for, separated by comma").Split(",")).Trim()));}
      "a" {$fExportAllErrors = "$TRUE"} ; # Select "$TRUE" or "$FALSE"
    };
    $fLogText = Foreach ( $fQueryComputer in $fQueryComputers.name) {
      Write-Host "Querying Computer: $($fQueryComputer)";
      Foreach ($fProfilePath in (gi \\$fQueryComputer\C$\ProgramData\FSLogix\Logs\Profile\Profile-*.log)[-$($fLogDays)..-1]) {
        Get-Content -Path $fProfilePath | Where-Object {($_ -like "*ERROR:*") -or ($_ -like "*WARN:*")} |Foreach  {
        New-Object psobject -Property @{
          Servername = $fQueryComputer
          Date = ($fProfilePath | Select -ExpandProperty CreationTime) | Get-Date -f "yyyy-MM-dd"
          Time = $_.split("]")[0].trim("[")
          tid = $_.split("]")[1].trim("[")
          Error = $_.split("]")[2].trim("[")
          LogText = $_.split("]")[3].trim("  ")
      }}};
      Foreach ($fProfilePath in (gi \\$fQueryComputer\C$\ProgramData\FSLogix\Logs\ODFC\ODFC-*.log)[-$($fLogDays)..-1]) {
        Get-Content -Path $fProfilePath | Where-Object {($_ -like "*ERROR:*") -or ($_ -like "*WARN:*")} |Foreach  {
        New-Object psobject -Property @{
          Servername = $fQueryComputer
          Date = ($fProfilePath | Select -ExpandProperty CreationTime) | Get-Date -f "yyyy-MM-dd"
          Time = $_.split("]")[0].trim("[")
          tid = $_.split("]")[1].trim("[")
          Error = $_.split("]")[2].trim("[")
          LogText = $_.split("]")[3].trim("  ")
      }}};
    };
    $fResult = Foreach ($fErrorCode in $fErrorCodes) {$fLogText | Where-Object { $_ -like "*$($fErrorCode)*" }};
  ## Output
    #$fResult | Sort DisplayName | Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
    #If ($fExportAllErrors -ne $true) { $fResult | sort Servername, Date, Time | FT Servername, Date, Time, Error, tid, LogText; Write-Host "   Number of errorcodes listed: $($fResult.count)`n"; };
    If ($fExportAllErrors -ne $true) { Write-Host "`n  Number of errorcodes listed: $($fResult.count)`n"; } else { Write-Host "`n  Number of errorcodes listed: $($fLogText.count)`n" };
  ## Exports
    #If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText) };
    If ($fExportAllErrors -ne $true) { 
      Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText)
	} else {
      Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fLogText | sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText)
	};
  ## Return
    [hashtable]$Return = @{};
    $Return.FSLogixErrors = $fResult | Sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText;
    Return $Return;
};

Function Get-ActiveADMxFiles { ## Get-ActiveADMxFiles from AD Server
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    # Define PolicyDefinition ADML Folder
    #$fPolicyDefs = "\\<FULLY_QUALIFIED_DOMAIN_NAME>\SYSVOL\<FULLY_QUALIFIED_DOMAIN_NAME>\Policies\PolicyDefinitions\en-US",
    $fPolicyDefs = "\\$($Env:USERDNSDOMAIN)\SYSVOL\$($Env:USERDNSDOMAIN)\Policies\PolicyDefinitions",
    $fFileNameText = "Get-ActiveADMxFiles"
  );
  Write-Host "`n`n  Reading GPO's";
  ## Generate a GPO report and capture it as XML
    [xml]$fGPOs = Get-GPOReport -All -ReportType Xml
  ## Parse captured XML
    $fPolicyInfo = @();
    For ($i = 0; $i -lt ($fGPOs.DocumentElement.GPO.Count); $i++) { 
        #Process Computer Policy
        For ($j = 0; $j -lt $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes.Count; $j++) { 
            if (($fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].type) -like "*:RegistrySettings") {
                if (!($fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy.Count -eq $null)) {
                    For ($k = 0; $k -lt $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy.Count; $k++) { 
                        $fPolInfo = "" | Select-Object gpoName, settingScope, settingName, settingState
                        $fPolInfo.gpoName = $fGPOs.DocumentElement.GPO[$i].Name
                        $fPolInfo.settingScope = "Computer"
                        $fPolInfo.settingName = $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy[$k].Name
                        $fPolInfo.settingState = $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy[$k].State
                        $fPolicyInfo += $fPolInfo
                    }
                }
                else {
                    $fPolInfo = "" | Select-Object gpoName, settingScope, settingName, settingState
                    $fPolInfo.gpoName = $fGPOs.DocumentElement.GPO[$i].Name
                    $fPolInfo.settingScope = "Computer"
                    $fPolInfo.settingName = $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy.Name
                    $fPolInfo.settingState = $fGPOs.DocumentElement.GPO[$i].Computer.ExtensionData.ChildNodes[$j].Policy.State
                    $fPolicyInfo += $fPolInfo
                };
            };
        };
        #Process User Policy
        For ($j = 0; $j -lt $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes.Count; $j++) { 
            if (($fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].type) -like "*:RegistrySettings") {
                if (!($fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy.Count -eq $null)) {
                    For ($k = 0; $k -lt $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy.Count; $k++) { 
                        $fPolInfo = "" | Select-Object gpoName, settingScope, settingName, settingState
                        $fPolInfo.gpoName = $fGPOs.DocumentElement.GPO[$i].Name
                        $fPolInfo.settingScope = "User"
                        $fPolInfo.settingName = $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy[$k].Name
                        $fPolInfo.settingState = $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy.State
                        $fPolicyInfo += $fPolInfo
                    }
                }
                else {
                    $fPolInfo = "" | Select-Object gpoName, settingScope, settingName, settingState
                    $fPolInfo.gpoName = $fGPOs.DocumentElement.GPO[$i].Name
                    $fPolInfo.settingScope = "User"
                    $fPolInfo.settingName = $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy.Name
    				$fPolInfo.settingState = $fGPOs.DocumentElement.GPO[$i].User.ExtensionData.ChildNodes[$j].Policy.State
                    $fPolicyInfo += $fPolInfo
                };
            };
        };
    };
  ## Get-ADMX-Files
  Write-Host "  Get and Read ADMX-Files";
    # Define output array
    $fAdmxResult = @();
    # Search ADMX files for policy settings
    $fAdmxFiles = Get-ChildItem -Path $fPolicyDefs -Recurse -Filter *.admx;
    $fAdmxResult = Foreach ($fAdmxFile in $fAdmxFiles) {
        $fAdmxContent = (Get-Content -Path ($fAdmxFile.FullName))
        #$out = "" | Select-Object gpoName, settingScope, settingName, settingState, admxFile, LastWriteTime
        Foreach ($fPolInfo in $fPolicyInfo) {
            $fADMXsettingName = $fPolInfo.settingName;
    		if ($fAdmxContent -like "*$fADMXsettingName*") {
                [pscustomobject]@{
                    gpoName = $fPolInfo.gpoName
                    settingScope = $fPolInfo.settingScope
                    settingName = $fPolInfo.settingName
                    settingState = $fPolInfo.settingState
                    admxFile = $fAdmxFile.Name
                    admxFilePath = $fAdmxFile.DirectoryName
                    LastWriteTime = $(get-date ($fAdmxFile.LastWriteTime) -f "yyyy-MM-dd HH.mm.ss")
                };
            };
        };
    };
  ## Get-ADML-Files
  Write-Host "  Get and Read ADML-Files";
    # Define output array
    $fAdmlResult = @();
    # Search ADML files for policy settings
    $fAdmlFiles = Get-ChildItem -Path $fPolicyDefs -Recurse -Filter *.adml;
    $fAdmlResult = Foreach ($fAdmlFile in $fAdmlFiles) {
        $fAdmlContent = (Get-Content -Path ($fAdmlFile.FullName))
        #$out = "" | Select-Object gpoName, settingScope, settingName, settingState, admlFile, LastWriteTime
        Foreach ($fPolInfo in $fPolicyInfo) {
            $fADMLsettingName = $fPolInfo.settingName
            if ($fAdmlContent -like "*$fADMLsettingName*") {
                [pscustomobject]@{
                  gpoName = $fPolInfo.gpoName
                  settingScope = $fPolInfo.settingScope
                  settingName = $fPolInfo.settingName
                  settingState = $fPolInfo.settingState
                  admlFile = $fAdmlFile.Name
                  admlFilePath = $fAdmlFile.DirectoryName
                  LastWriteTime = $(Get-Date ($fAdmlFile.LastWriteTime) -f "yyyy-MM-dd HH.mm.ss")
               };
            };
        };
    };
  Write-Host "  Preparing Data for Output and Export`n`n";
  ## Get-ADMX-Files Results
    $fAdmxFilesUnique = $fAdmxResult | Sort admxFile -Unique | Select admxFile, admxFilePath, LastWriteTime;
  ## Get-ADML-Files
    $fAdmlFilesUnique = $fAdmlResult | Sort admlFile -Unique | Select admlFile, admlFilePath, LastWriteTime;
  ## Get-ADML-Files from ADMX-Filename
    #$fAdmxAdmlFiles = Foreach ($fAdmxFile in $fAdmxFiles) {Get-ChildItem -Path $fPolicyDefs -Recurse | ? {$_.basename -eq $fAdmxFile.basename} | Select @{Name="ADMX-file";Expression={$fAdmxFile.Name}}, @{Name="ADML-file";Expression={$_.Fullname}}, @{Name="ADMX-file LastWriteTime";Expression={$fAdmxFile.LastWriteTime}}, @{Name="ADML-file LastWriteTime";Expression={$_.LastWriteTime}}};
    $fAdmxAdmlFiles = Foreach ($fAdmxFile in $fAdmxFiles) {$fAdmlFiles | ? {$_.basename -eq $fAdmxFile.basename} | Select @{Name="ADMX-file";Expression={$fAdmxFile.Name}}, @{Name="ADML-file";Expression={$_.Fullname}}, @{Name="ADMX-file LastWriteTime";Expression={$fAdmxFile.LastWriteTime}}, @{Name="ADML-file LastWriteTime";Expression={$_.LastWriteTime}}};
  ## Output
  ## ADMX-Files Results
    #$fAdmxResult | Sort admxFile | FT; $fAdmxFilesUnique | FT;
    #Write-Host "  Used ADMX GPO: $($fAdmxResult.count) - ADMX files in use (Unique): $($fAdmxFilesUnique.count)";
  ## ADML-Files Results
    #$fAdmlResult | Sort admlFile | FT; $fAdmlFilesUnique | FT;
    #Write-Host "  Used ADML GPO: $($fAdmlResult.count) - ADML files in use (Unique): $($fAdmlFilesUnique.count)";
  ## ADMX+ADML-Files Results
    #$fAdmxAdmlFiles;
  ## Output Overview
    #Write-Host "  Used ADMX GPO: $($fAdmxResult.count) - ADMX files in use (Unique): $($fAdmxFilesUnique.count)";
    #Write-Host "  Used ADML GPO: $($fAdmlResult.count) - ADML files in use (Unique): $($fAdmlFilesUnique.count)";
  ## Exports
  ## Export ADMX-Files
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMX" -fCustomerName $fCustomerName -fExportData $($fAdmxResult) };
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMX_Unique" -fCustomerName $fCustomerName -fExportData $($fAdmxFilesUnique) };
  ## Export ADML-Files
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADML" -fCustomerName $fCustomerName -fExportData $($fAdmlResult) };
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADML_Unique" -fCustomerName $fCustomerName -fExportData $($fAdmlFilesUnique) };
  ## Export ADMX+ADML-Files
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMXADMLFiles" -fCustomerName $fCustomerName -fExportData $($fAdmxAdmlFiles) };

  ## Return 
    [hashtable]$Return = @{};
    $Return.admxResult = $fAdmxResult | Sort admxFile;
    $Return.admlResult = $fAdmlResult | Sort admlFile;
    $Return.admxFilesUnique = $fAdmxFilesUnique;
    $Return.admlFilesUnique = $fAdmlFilesUnique;
    $Return.admxadmlFiles = $fAdmxAdmlFiles;
    $Return.admxCounts = "  Used ADMX GPO: $($fAdmxResult.count) - ADMX files in use (Unique): $($fAdmxFilesUnique.count)";
    $Return.admlCounts = "  Used ADML GPO: $($fAdmlResult.count) - ADML files in use (Unique): $($fAdmlFilesUnique.count)";
    Return $Return;
};
Function Get-FolderPermissionLocal { ## 
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fFolderPaths = ($Entry = @(((Read-Host "  Enter FolderPath(s) to get Permission list, separated by comma ").Split(",")).Trim())),
    $fExport = ("Yes" | %{ If($Entry = Read-Host "  Export result to file ( Y/N - Default: $_ )"){$Entry} Else {$_} }),
    $fFileNameText = "Get-FolderPermission_$($ENV:Computername)"
  );
  ## Script
    Show-Title "Get Folder Permissions on Local Computer/Server";
    $fResult = ForEach ($fFolderPath in $fFolderPaths) {
      $fFolders = Get-ChildItem -Directory -Path "$($fFolderPath)" -Recurse -Force;
      ForEach ($fFolder in $fFolders) {
        $fAcl = Get-Acl -Path $fFolder.FullName;
        ForEach ($fAccess in $fAcl.Access) {
          New-Object PSObject -Property ([ordered]@{
            'FolderName'=$fFolder.FullName;
            'Group/User'=$fAccess.IdentityReference;
            'Permissions'= $fAccess.FileSystemRights;
            'Inherited'=$fAccess.IsInherited;
      });};};};
    $fResultLevel_01_02 = ForEach ($fFolderPath in $fFolderPaths) {
      $fFoldersLevel_01 = Get-ChildItem -Directory -Path "$($fFolderPath)"
      $fFoldersLevel_02 = Foreach ($Folder in $fFoldersLevel_01.fullname) {Get-ChildItem -Directory -Path $Folder}
      $fFoldersLevel_01_02 = ($fFoldersLevel_01+$fFoldersLevel_02 | Sort FullName)
      ForEach ($fFolder in $fFoldersLevel_01_02) {
        $fAcl = Get-Acl -Path $fFolder.FullName;
        ForEach ($fAccess in $fAcl.Access) {
          New-Object PSObject -Property ([ordered]@{
            'FolderName'=$fFolder.FullName;
            'Group/User'=$fAccess.IdentityReference;
            'Permissions'= $fAccess.FileSystemRights;
            'Inherited'=$fAccess.IsInherited;
      });};};};
  ## Output
    #$fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited | FT -autosize;
	#$fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited | FT -autosize;
  ## Exports
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited) };
    If (($fExport -eq "Y") -or ($fExport -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_FoldersLevel_01_02" -fCustomerName $fCustomerName -fExportData $($fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited) };
  ## Return
    [hashtable]$Return = @{};
    $Return.FolderPermission = $fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited;
	$Return.FolderPermission_Level_01_02 = $fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited;
    Return $Return;
};
### End Functions
ToolboxMenu;
