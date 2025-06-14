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
Function Get-ExportHTML { Param ( $fExportHTML = ("Yes" | %{ If($Entry = Read-Host "  Export result to HTML-file ( Y/N - Default: $_ )"){$Entry} Else {$_} }) );
  Return $fExportHTML;
};
Function Get-ExportCSV { Param ( $fExportCSV = ("Yes" | %{ If($Entry = Read-Host "  Export result to CSV-file  ( Y/N - Default: $_ )"){$Entry} Else {$_} }) );
  Return $fExportCSV;
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
Function Export-HTMLData { Param ( $fFileNameText, $fCustomerName, $fExportData ); ##
  # Add this line to Params: $fFileNameText = "<FILENAME>"    /    $fFileNameText = "<FILENAME>",
  # Add this line to Script: If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $(<EXPORTDATA>) };
  <#
    [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
    $ExportData.SiteTitle = $fTitle; # $ExportData.SiteTitle = "Example_Title";
    $ExportData.Title1 = "Menu_1"; $ExportData.Content1 = $Data1 | ConvertTo-HTML -Fragment
    $ExportData.Title2 = "Menu_2"; $ExportData.Content2 = $Data2 | ConvertTo-HTML -Fragment
    $ExportData.Title3 = "Menu_3"; $ExportData.Content3 = $Data3 | ConvertTo-HTML -Fragment
  #>
  $fFileNameBase = "$($fCustomerName)$(($fFileNameText).Split([IO.Path]::GetInvalidFileNameChars()) -join '_')_($(get-date -f "yyyy-MM-dd_HH.mm"))";
  $fFileName = "$([Environment]::GetFolderPath("Desktop"))\$($fFileNameBase)";
  #$fFileName = "$($env:USERPROFILE)\Desktop\$($fFileNameBase)";
<### HTML Site ###>
## HTML header
# ITM8 White: https://itm8.dk/hubfs/BRANDING/brand-guidelines/itm8-white-vector.svg
# ITM8 Purple: https://itm8.dk/hubfs/BRANDING/brand-guidelines/itm8-purple-vector.svg
# ITM8 Logo: https://itm8.dk/hs-fs/hubfs/BRANDING/itm8-rgb-tall.png"
$header = @"
<head>
  <title>$($fExportData.SiteTitle)</title>
  <link rel="shortcut icon" href="https://itm8.dk/hubfs/BRANDING/itm8_favicon_logo_16x16px.png">
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
<style>
.tab-pane th, .tab-pane td {
  padding: 1px 5px;
  vertical-align: top; 
}
.tab-pane th {
  onclick="sortTable(1)"
}
.tab-pane tr:nth-child(odd) {
  background-color: #f2f2f2
}
</style>
</head>
"@ ## END HTML header
#
## Main layout
$layout = @"
<body>
<div class="container">
  <img src="https://itm8.dk/hubfs/BRANDING/brand-guidelines/itm8-purple-vector.svg" height="50" style="padding-top: 8px;">
  <table style="width:100%"><tr><td><h2>$($fExportData.SiteTitle)</h2></td><td align="Right" valign="Bottom"><style="margin-bottom: 0px;" id='CreationDate'>Creation Date: $(Get-Date)</td></tr></table>
  <!-- Menu Panes -->
  <ul class="nav nav-tabs">
    <li class="active"><a data-toggle="tab" href="#menu1">$($fExportData.Title1)</a></li>
    $(if ($($fExportData.Content2)) {" <li><a data-toggle='tab' href='#menu2'>$($fExportData.Title2)</a></li> "})
    $(if ($($fExportData.Content3)) {" <li><a data-toggle='tab' href='#menu3'>$($fExportData.Title3)</a></li> "})
    $(if ($($fExportData.Content4)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title4)</a></li> "})
    $(if ($($fExportData.Content5)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title5)</a></li> "})
    $(if ($($fExportData.Content6)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title6)</a></li> "})
    $(if ($($fExportData.Content7)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title7)</a></li> "})
    $(if ($($fExportData.Content8)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title8)</a></li> "})
    $(if ($($fExportData.Content9)) {" <li><a data-toggle='tab' href='#menu4'>$($fExportData.Title9)</a></li> "})
  </ul>
  <!-- Menu Data Display -->
  <div class="tab-content">
    <div id="menu1" class="tab-pane fade in active">
      <h3>$($fExportData.Title1)</h3>
      <p>$($fExportData.Content1)</p>
    </div>
    $(if ($($fExportData.Content2)) {"
      <div id='menu2' class='tab-pane fade'>
        <h3>$($fExportData.Title2)</h3>
        <p>$($fExportData.Content2)</p>
      </div>
    "})
    $(if ($($fExportData.Content3)) {"
      <div id='menu3' class='tab-pane fade'>
        <h3>$($fExportData.Title3)</h3>
        <p>$($fExportData.Content3)</p>
      </div>
    "})
    $(if ($($fExportData.Content4)) {"
      <div id='menu4' class='tab-pane fade'>
        <h3>$($fExportData.Title4)</h3>
        <p>$($fExportData.Content4)</p>
      </div>
    "})
    $(if ($($fExportData.Content5)) {"
      <div id='fExportData' class='tab-pane fade'>
        <h3>$($fExportData.Title5)</h3>
        <p>$($fExportData.Content5)</p>
      </div>
    "})
    $(if ($($fExportData.Content6)) {"
      <div id='menu6' class='tab-pane fade'>
        <h3>$($fExportData.Title6)</h3>
        <p>$($fExportData.Content6)</p>
      </div>
    "})
    $(if ($($fExportData.Content7)) {"
      <div id='menu7' class='tab-pane fade'>
        <h3>$($fExportData.Title7)</h3>
        <p>$($fExportData.Content7)</p>
      </div>
    "})
    $(if ($($fExportData.Content8)) {"
      <div id='menu8' class='tab-pane fade'>
        <h3>$($fExportData.Title8)</h3>
        <p>$($fExportData.Content8)</p>
      </div>
    "})
    $(if ($($fExportData.Content9)) {"
      <div id='menu9' class='tab-pane fade'>
        <h3>$($fExportData.Title9)</h3>
        <p>$($fExportData.Content9)</p>
      </div>
    "})
  </div>   <!-- END class="tab-content" -->
</div>   <!-- END class="container" -->
</body>
"@ ## END Main layout
#
#The command below will combine all the information gathered into a single HTML report
#$Report = ConvertTo-HTML -Body "$layout" -Title "Computer Information Report" -Head $header -PostContent "<p>Creation Date: $(Get-Date)<p>"
$Report = ConvertTo-HTML -Body "$layout" -Head $header
#
#The command below will generate the report to an HTML file
$Report | Out-File "$($fFileName).html"; ii "$($fFileName).html"
}; # End Function Export-HTMLData
Function Export-CSVData { Param ( $fFileNameText, $fCustomerName, $fExportData ); ##
  # Add this line to Params: $fFileNameText = "<FILENAME>"    /    $fFileNameText = "<FILENAME>",
  # Add this line to Script: If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $(<EXPORTDATA>) };
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
  If ($DomainQueryEnabled -eq $True) {Write-Host "  Press  '9'  for Get Password Never Expires for AD User Accounts."};
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
  Write-Host "   Press 'X'  to Exit.";
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
      "9" { "`n`n  You selected: Get Password Never Expires for AD User Accounts`n"
          If ($DomainQueryEnabled -eq $True) {$Result = Get-ADUserPasswordNeverExpires; $Result.count; $Result.UserPasswordNeverExpires | FT -Autosize;} ELSE {$DomainQueryEnabledInfo}
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
  } until (($selection -eq "x") -or ($selection -eq "q") -or ($selection -eq "0"));
};
## End Start Menu
### Functions
Function Get-LatestRebootLocal { ### Get-LatestReboot - Get Latest Reboot / Restart / Shutdown for logged on server
  Param(
    $fEventLogStartTime = (Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-LatestReboot_$($ENV:Computername)",
    $fTitle = "Get latest Shutdown / Restart / Reboot for Local Server - Events After: $($fEventLogStartTime)"
  );
  ## Script
    Show-Title $fTitle
    $fLatestBootTime = Get-WmiObject win32_operatingsystem | select @{LABEL="MachineName";EXPRESSION={$_.csname}}, @{LABEL="LastBootUpTime";EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}};
    $fResult = Get-EventLog -LogName System -After $fEventLogStartTime | Where-Object {($_.EventID -eq 1074) -or ($_.EventID -eq 6008) -or ($_.EventID -eq 41)};
    IF (!($fResult)){$fResult = [pscustomobject]@{MachineName = $($Env:COMPUTERNAME);TimeGenerated = ""; UserName = "$($($Env:COMPUTERNAME)) is not rebooted in the query periode" }};
  ## Output
    # $fResult | Select MachineName, TimeGenerated, UserName, Message | fl; $fResult | Select MachineName, TimeGenerated, UserName | ft -Autosize; $fLatestBootTime;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle
      $ExportData.Title1 = "Latest BootTime"; $ExportData.Content1 = $fLatestBootTime | ConvertTo-HTML -Fragment
      $ExportData.Title2 = "Latest Reboot"; $ExportData.Content2 = $($fResult | Select MachineName, TimeGenerated, UserName) | ConvertTo-HTML -Fragment
      $ExportData.Title3 = "Latest Reboot (Extended)"; $ExportData.Content3 = $($fResult | Select MachineName, TimeGenerated, UserName, Message) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName, Message) };
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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fJobNamePrefix = "LatestReboot_",
    $fFileNameText = "Servers_Get-LatestReboot",
    $fTitle = "Get latest Shutdown / Restart / Reboot for multiple Domain Servers - Events After: $($fEventLogStartTime)"
  );
  ## Script
    Show-Title $fTitle;
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
    $fResult = $($fResult;$fLocalHostResult);
  ## Output
    #$fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Latest Reboot"; $ExportData.Content1 =  $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName) | ConvertTo-HTML -Fragment
      $ExportData.Title2 = "Latest Reboot (Extended)"; $ExportData.Content2 =$($fResult | Sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName, Message) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) {
      Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName);
      Export-CSVData -fFileNameText "$($fFileNameText)_Extended" -fCustomerName $fCustomerName -fExportData $($fResult | Sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName, Message);
    };
  ## Return
    [hashtable]$Return = @{};
    $Return.LatestBootEvents = $fResult | sort MachineName, TimeGenerated | Select MachineName, TimeGenerated, UserName;
    Return $Return;
};
Function Get-LoginLogoffLocal { ## Get-LoginLogoff from Logged On for Local Computer/Server
  Param(
    $fEventLogStartTime = $(Get-LogStartTime -DefaultDays "7" -DefaultHours "12"),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-LatestLoginLogoff_$($ENV:Computername)",
    $fTitle = "Get latest Login / Logoff for Local Computer/Server - Events After: $($fEventLogStartTime)"
  );
  ## Default Variables
    $fUserProperty = @{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}}
    $fTypeProperty = @{n="Action";e={if($_.EventID -eq 7001) {"Logon"} elseif ($_.EventID -eq 7002){"Logoff"} else {"other"}}}
    $fTimeProperty = @{n="Time";e={$_.TimeGenerated}}
    $fMachineNameProperty = @{n="MachineName";e={$_.MachineName}}
  ## Script
    Show-Title $fTitle;
    Write-Host "Querying Computer: $($ENV:Computername)"
    $fResult = Get-EventLog System -Source Microsoft-Windows-Winlogon -after $fEventLogStartTime | select $fUserProperty,$fTypeProperty,$fTimeProperty,$fMachineNameProperty
  ## Output
    #$fResult | sort User, Time | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Latest Login-Logoff"; $ExportData.Content1 = $fResult | sort User, Time | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort User, Time) };
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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Servers_Get-LatestLoginLogoff",
    $fTitle = "Get latest Login / Logoff  for multiple Domain Servers - Events After: $($fEventLogStartTime)"
  );
  ## Default Variables
    $fUserProperty = @{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}};
    $fTypeProperty = @{n="Action";e={if($_.EventID -eq 7001) {"Logon"} elseif ($_.EventID -eq 7002){"Logoff"} else {"other"}}};
    $fTimeProperty = @{n="Time";e={$_.TimeGenerated}};
    $fMachineNameProperty = @{n="MachineName";e={$_.MachineName}};
  ## Script
    Show-Title $fTitle;
    $fResult = foreach ($fComputer in $fQueryComputers.name) { # Get Values like .Name, .DNSHostName
      Write-Host "Querying Computer: $($fComputer)"
      Get-EventLog System -Source Microsoft-Windows-Winlogon -ComputerName $fComputer -after $fEventLogStartTime | Select $fUserProperty,$fTypeProperty,$fTimeProperty,$fMachineNameProperty;
    };
  ## Output
    #$fResult | sort User, Time | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Latest Login-Logoff"; $ExportData.Content1 =  $($fResult | sort User, Time ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort User, Time) };
  ## Return
    [hashtable]$Return = @{};
    $Return.LoginLogoff = $fResult | sort User, Time;
    Return $Return;
};
Function Get-ADUsers {## Get AD Users
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "ADUsers",
    $fTitle = "Get AD Users"
  );
  ## Script
    Show-Title $fTitle;
    $fResult = Get-Aduser -Filter * -Properties *  | Sort-Object -Property samaccountname | Select CN, DisplayName, Samaccountname,@{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled, LockedOut, PasswordNeverExpires, @{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}}, Description;
  ## Output
    #$fResult | Sort DisplayName | Select CN, DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Latest Reboot"; $ExportData.Content1 =  $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ADUsers = $fResult | Sort DisplayName | Select CN, DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description;
    Return $Return;
};
Function Get-InactiveADUsers {## Get inactive AD Users / Latest Logon more than eg 90 days
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fDaysInactive = ("90" | %{ If($Entry = Read-Host "  Enter number of inactive days (Default: $_ Days)"){$Entry} Else {$_} }),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Inactive_ADUsers_last_$($fDaysInactive)_days",
    $fTitle = "Get AD Users Latest Logon / inactive more than $($fDaysInactive) days"
  );
  ## Script
    Show-Title $fTitle;
    $fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-Aduser -Filter {(LastLogonTimeStamp -lt $fDaysInactiveTimestamp) -or (LastLogonTimeStamp -notlike "*")} -Properties *  | Sort-Object -Property samaccountname | Select CN,DisplayName,Samaccountname,@{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}},Enabled,LockedOut, PasswordNeverExpires,@{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}},Description;
  ## Output
    #$fResult | Sort DisplayName | Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Inactive ADUsers"; $ExportData.Content1 =  $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort DisplayName | Select CN,DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description) };
  ## Return
    [hashtable]$Return = @{};
    $Return.InactiveADUsers = $fResult | Sort DisplayName | Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
    Return $Return;
};
Function Get-InactiveADComputers {## Get inactive AD Computers / Latest Logon more than eg 90 days
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fDaysInactive = ("90" | %{ If($Entry = Read-Host "  Enter number of inactive days (Default: $_ Days)"){$Entry} Else {$_} }),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Inactive_ADComputers_last_$($fDaysInactive)_days",
    $fTitle = "Get AD Computers Latest Logon / inactive more than $($fDaysInactive) days"
  );
  ## Script
    Show-Title $fTitle;
    $fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-ADComputer -Filter {LastLogonDate -lt $fDaysInactiveTimestamp } -Properties CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName | Sort-Object -Property CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Output
    #$fResult | Sort CN | Select CN, LastLogonDate, OperatingSystem, CanonicalName;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Latest AD Computers Logon"; $ExportData.Content1 =  $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.InactiveADComputers = $fResult | Sort CN | Select CN, LastLogonDate, OperatingSystem, Enabled, CanonicalName;
    Return $Return;
};
Function Get-ADServers {## Get AD Servers
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "ADServers",
    $fTitle = "Get AD Server"
  );
  ## Script
    Show-Title $fTitle;
    $fResult = Get-ADComputer -Filter {(operatingsystem -like "*server*") } -Properties CN, LastLogonDate, OperatingSystem, CanonicalName | Sort-Object -Property CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Output
    #$fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "AD Servers"; $ExportData.Content1 =  $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ADServers = $fResult | Sort CN | Select CN, LastLogonDate, Enabled, OperatingSystem, CanonicalName;
    Return $Return;
};
Function Get-ADUserPasswordNeverExpires {## Get Password Never Expires for AD User Accounts
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "UserPasswordNeverExpires",
    $fTitle = "Get Password Never Expires for AD User Accounts"
  );
  ## Script
    Show-Title $fTitle;
    $fDaysInactiveTimestamp = [DateTime]::Now.AddDays(-$($fDaysInactive));
    $fResult = Get-ADUser -Filter * -Properties Name, LockedOut, PasswordNeverExpires, pwdlastSet | where { $_.passwordNeverExpires -eq $true } | Sort Name | Select-Object Name, SamAccountName, LockedOut, @{n="PwdNeverExpires";e={$_.PasswordNeverExpires}}, @{n="PwdLastSet";e={[datetime]::FromFileTime($_."PwdLastSet").ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled;
  ## Output
    #$fResult;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Password Never Expires"; $ExportData.Content1 =  $($fResult ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult) };
  ## Return
    [hashtable]$Return = @{};
    $Return.UserPasswordNeverExpires = $fResult;
    Return $Return;
};
Function Get-ITM8Users {## Get ITM8 AD Users
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "ITM8_Users",
    $fTitle = "Get ITM8 AD Users"
  );
  ## Script
    Show-Title $fTitle;
    $fResult = Get-ADUser -Filter * -Properties * | ? { ($_.DistinguishedName -Like "*OU=ITM8*") -or ($_.Description -like "*ITM8*") -or ($_.Samaccountname -like "*ITM8*") -or ($_.DisplayName -like "*ITM8*") -or ($_.DistinguishedName -Like "*OU=Progressive*") -or ($_.Description -like "*Progressive*") -or ($_.Samaccountname -like "*ProAdmin*") -or ($_.DisplayName -like "*ProAdmin*") -or ($_.Samaccountname -like "*PIT-Support*") -or ($_.DisplayName -like "*PIT-Support*") -or ($_.Samaccountname -like "*DTAdmin*") -or ($_.DisplayName -like "*DTAdmin*")} | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, @{n="LastLogonDate";e={[datetime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")}}, Enabled, LockedOut, PasswordNeverExpires, @{Name='PwdLastSet';Expression={[DateTime]::FromFileTime($_.PwdLastSet).ToString("yyyy-MM-dd HH:mm:ss")}}, Description, DistinguishedName;
  ## Output
    #$fResult.count; $fResult | Sort Enabled, DisplayName | ft ;# Select CN,DisplayName,Samaccountname,LastLogonDate,Enabled,LockedOut, PasswordNeverExpires,PwdLastSet,Description;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "ITM8 AD Users"; $ExportData.Content1 =  $($fResult | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description, DistinguishedName ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description, DistinguishedName) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ITM8Users = $fResult | Sort Enabled, DisplayName | Select DisplayName, Samaccountname, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, PwdLastSet, Description, DistinguishedName;
    Return $Return;
};
Function Get-HotFixInstallDatesLocal { ### Get-HotFixInstallDates for Local Computer/Server
  Param(
    $fHotfixInstallDates = ("3" | %{ If($Entry = Read-Host "  Enter number of Hotfix-install dates per Computer (Default: $_ Install Dates)"){$Entry} Else {$_} }),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-HotFixInstallDates_$($ENV:Computername)",
    $fTitle = "Get latest $($fHotfixInstallDates) HotFix Install Dates Local Computer/Server"
    );
  ## Script
    Show-Title $fTitle;
    $fResult = Get-Hotfix | sort InstalledOn -Descending -Unique -ErrorAction SilentlyContinue | Select -First $fHotfixInstallDates | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
    $fResult | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$((Get-ComputerInfo).WindowsProductName)";
    $fResult | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$((Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -notlike '127.0.0.1' }).IPAddress)";
  ## Output
    #$fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "HotFix Install Dates"; $ExportData.Content1 =  $($fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
  ## Return
    [hashtable]$Return = @{};
    $Return.HotFixInstallDates = $fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address;
    Return $Return;
};
Function Get-HotFixInstallDatesDomain { ### Get-HotFixInstallDates for multiple Domain servers
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fHotfixInstallDates = ("3" | %{ If($Entry = Read-Host "  Enter number of Hotfix-install dates per Computer (Default: $_ Install Dates)"){$Entry} Else {$_} }),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Servers_Get-HotFixInstallDates",
    $fTitle = "Get latest $($fHotfixInstallDates) HotFix Install Dates multiple Domain Servers"
    );
  ## Script
    Show-Title $fTitle;
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
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "HotFix Install Dates"; $ExportData.Content1 =  $($fResult | sort PSComputerName | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort PSComputerName | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
  ## Return
    [hashtable]$Return = @{};
    $Return.HotFixInstallDates = $fResult | sort PSComputerName, InstalledOn | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address;
    Return $Return;
};
Function Get-HotFixInstalledLocal { ### Get-HotFixInstalled on Local Computer/Server
  Param(
    $fHotfixInstallDays = ("90" | %{ If($Entry = Read-Host "  Enter number of days for Installed Hotfixes on Local Computer/Server (Default: $_ Install Days)"){$Entry} Else {$_} }),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-HotFixInstalled_$($ENV:Computername)",
    $fTitle = "Get Installed HotFixes for latest $($fHotfixInstallDays) days on Local Computer/Server"
  );
  ## Script
    Show-Title $fTitle;
    $fResult = Get-Hotfix | sort InstalledOn -Descending -ErrorAction SilentlyContinue | ? { $_.InstalledOn -gt $((Get-Date "0:00").adddays(-$($fHotfixInstallDays)))} | Select PSComputerName, @{n='InstalledOn';e={Get-Date $_.InstalledOn -Format yyyy-MM-dd}}, InstalledBy, Description, HotFixID;
    $fResult | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value "$((Get-ComputerInfo).WindowsProductName)";
    $fResult | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value "$((Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -notlike '127.0.0.1' }).IPAddress)";
  ## Output
    #$fResult | sort InstalledOn, HotFixID -Descending | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "HotFix Installed"; $ExportData.Content1 =  $($fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | sort @{Expression = "MachineName"; Descending = $false},  @{Expression = "InstalledOn"; Descending = $true} | Select PSComputerName, InstalledOn, InstalledBy, Description, HotFixID, OperatingSystem, IPv4Address) };
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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-Expired_Certificates",
    $fTitle = "Get Certificates expired or expire within next $($fExpiresBeforeDays) days on Local Server"
  );
  ## Script
    Show-Title $fTitle;
    $fExpiresBefore = [DateTime]::Now.AddDays($($fExpiresBeforeDays));
    $fResult = Get-ChildItem -path "cert:LocalMachine\my" -Recurse | ? {$_.NotAfter -lt "$fExpiresBefore"} | ? {($_.Subject -like $fCertSearch) -or ($_.FriendlyName -like $fCertSearch)} | Select @{Name="ServerName";Expression={$env:COMPUTERNAME}}, @{Name="Expires";Expression={($_.NotAfter).ToString("yyyy-MM-dd HH:mm:ss")}}, FriendlyName, Subject, @{Name="ParentPath";Expression={$_.PSParentPath.Replace("Microsoft.PowerShell.Security\Certificate::","")}}, Issuer, Thumbprint;
  ## Output
    #$fResult | Sort Expires, FriendlyName | Select Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Expired Certificates"; $ExportData.Content1 =  $($fResult |  sort Expires, FriendlyName | Select ServerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult |  sort Expires, FriendlyName | Select ServerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint) };
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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fJobNamePrefix = "ExpiredCertificates_",
    $fFileNameText = "Servers_Get-Expired_Certificates",
    $fTitle = "Get Certificates expired or expire within next $($fExpiresBeforeDays) days on multiple Domain Servers"
  );
  ## Script
    Show-Title $fTitle;
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
    $fResult = $($fResult;$fLocalHostResult);
  ## Output
    #$fResult | Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint | FT -autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Expired Certificates"; $ExportData.Content1 =  $($fResult |  Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult |  Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint) };
  ## Return
    [hashtable]$Return = @{};
    $Return.ExpiredCertificates = $fResult |  Sort PSComputerName, Expires, FriendlyName | Select PSComputerName, Expires, FriendlyName, Subject, ParentPath, Issuer, Thumbprint;
    Return $Return;
};
Function Get-NetAdapterInfoDomain {
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV), 
    $fJobNamePrefix = "NetAdapterInfo_",
    $fFileNameText = "NetAdapterInfo",
    $fTitle = "Get Network Adapter information"
  );
  ## Script
    Show-Title $fTitle;
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
      $fResult = $($fResult;$fLocalHostResult); $fResult = $fResult | Sort DHCP, ComputerName, InterfaceAlias | Select ComputerName, DHCP, IPAdresses, DNSServers, InterfaceAlias;
 ## Output
    #$fResult | FT -Autosize;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Network Adapter info"; $ExportData.Content1 =  $($fResult ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult;)};
   ## Return
    [hashtable]$Return = @{}; 
    $Return.NetAdapterInfo = $fResult;
    Return $Return;
};
Function Get-TimeSyncStatusDomain {## Get TimeSync Status (Registry) - need an AD Server or Server with RSAT
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fJobNamePrefix = "TimeSyncStatus_",
    $fFileNameText = "TimeSyncStatus",
    $fTitle = "Get TimeSync Status (Registry)"
  );
  ## Script
    Show-Title $fTitle;
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
    $fResult = $($fResult;$fLocalHostResult);
  ## Output
    #$fResult | Sort Servername | FT Servername, NTPServer, NTPType, TimeServiceStatus;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "TimeSync Status (Registry)"; $ExportData.Content1 =  $($fResult | Sort Servername | Select Servername, NTPServer, NTPType, TimeServiceStatus ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Servername | Select Servername, NTPServer, NTPType, TimeServiceStatus) };
  ## Return
    [hashtable]$Return = @{};
    $Return.TimeSyncStatus = $fResult | Sort Servername | FT Servername, NTPServer, NTPType, TimeServiceStatus;
    Return $Return;
};
Function Get-DateTimeStatusDomain {## Get Date & Time Status - need an AD Server or Server with RSAT
  Param(
    $fCustomerName = $(Get-CustomerName),
    $fQueryComputers = $(Get-QueryComputers),
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fJobNamePrefix = "DateTimeStatus_",
    $fFileNameText = "DateTimeStatus",
    $fTitle = "Get Date and Time status from Domain Servers"
  );
  ## Script
    Show-Title $fTitle;
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
    $fResult = $($fResult;$fLocalHostResult);
  ## Output
    #$fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone;
  ## Exports
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Date & Time Status"; $ExportData.Content1 =  $($fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort PSComputerName | Select PSComputerName, InternetTime, LocalTime, LocalNTPServer, LocalCulture, LocalTimeZone, InternetTimeZone) };
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
    $fExportHTML = (Get-ExportHTML),
    #$fExportCSV = (Get-ExportCSV),
    $fFileNameText = "FSLogixErrors",
    $fTitle = "Get FSLogix Errors for past $($fLogDays) days",
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
    Show-Title $fTitle;
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
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "FSLogix Errors"; $ExportData.Content1 =  $($fResult | sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText ) | ConvertTo-HTML -Fragment
      $ExportData.Title2 = "FSLogix Errors (All Errors)"; $ExportData.Content2 =  $($fLogText | sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    #If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort Servername, Date, Time | Select Servername, Date, Time, Error, tid, LogText) };
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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    # Define PolicyDefinition ADML Folder
    #$fPolicyDefs = "\\<FULLY_QUALIFIED_DOMAIN_NAME>\SYSVOL\<FULLY_QUALIFIED_DOMAIN_NAME>\Policies\PolicyDefinitions\en-US",
    $fPolicyDefs = "\\$($Env:USERDNSDOMAIN)\SYSVOL\$($Env:USERDNSDOMAIN)\Policies\PolicyDefinitions",
    $fFileNameText = "Get-ActiveADMxFiles",
    $fTitle = "Get Active ADMx-Files from AD Server"
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
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "ADMX-Files "; $ExportData.Content1 =  $($fAdmxResult ) | ConvertTo-HTML -Fragment
      $ExportData.Title2 = "ADMX-Files (Unique)"; $ExportData.Content2 =$($fAdmxFilesUnique ) | ConvertTo-HTML -Fragment
      $ExportData.Title3 = "ADML-Files "; $ExportData.Content3 =  $($fAdmlResult ) | ConvertTo-HTML -Fragment
      $ExportData.Title4 = "ADML-Files (Unique)"; $ExportData.Content4 =$($fAdmlFilesUnique ) | ConvertTo-HTML -Fragment
      $ExportData.Title5 = "ADMX+ADML-Files "; $ExportData.Content5 =  $($fAdmxAdmlFiles ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
  ## Export ADMX-Files
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMX" -fCustomerName $fCustomerName -fExportData $($fAdmxResult) };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMX_Unique" -fCustomerName $fCustomerName -fExportData $($fAdmxFilesUnique) };
  ## Export ADML-Files
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADML" -fCustomerName $fCustomerName -fExportData $($fAdmlResult) };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADML_Unique" -fCustomerName $fCustomerName -fExportData $($fAdmlFilesUnique) };
  ## Export ADMX+ADML-Files
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_ADMXADMLFiles" -fCustomerName $fCustomerName -fExportData $($fAdmxAdmlFiles) };

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
    $fExportHTML = (Get-ExportHTML),
    $fExportCSV = (Get-ExportCSV),
    $fFileNameText = "Get-FolderPermission_$($ENV:Computername)",
    $fTitle = "Get Folder Permissions on Local Computer/Server"
  );
  ## Script
    Show-Title $fTitle;
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
    If (($fExportHTML -eq "Y") -or ($fExportHTML -eq "YES")) { 
      [hashtable]$ExportData = @{}; # Add up to 9 Title- and Content-variables
      $ExportData.SiteTitle = $fTitle;
      $ExportData.Title1 = "Folder Permissions"; $ExportData.Content1 =  $($fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited ) | ConvertTo-HTML -Fragment
      $ExportData.Title2 = "Folder Permissions (2 Folder-Levels)"; $ExportData.Content2 =$($fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited ) | ConvertTo-HTML -Fragment
      Export-HTMLData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $ExportData
    };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)" -fCustomerName $fCustomerName -fExportData $($fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited) };
    If (($fExportCSV -eq "Y") -or ($fExportCSV -eq "YES")) { Export-CSVData -fFileNameText "$($fFileNameText)_FoldersLevel_01_02" -fCustomerName $fCustomerName -fExportData $($fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited) };
  ## Return
    [hashtable]$Return = @{};
    $Return.FolderPermission = $fResult | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited;
    $Return.FolderPermission_Level_01_02 = $fResultLevel_01_02 | Sort FolderName, "Group/User" | Select FolderName, "Group/User", Permissions, Inherited;
    Return $Return;
};
### End Functions
ToolboxMenu;
