Add-Type -AssemblyName System.Windows.Forms

### Variables
<#
SSL Ports:
443
444
8443
8444
9443
9444
10443
10444

NAV ports: 
7046
7047 - Web services default port
7048
8145
8146
#>

$SSLPorts = @("443", "444", "8443", "8444", "9443", "9444", "10443", "10444", "7046", "7047", "7048", "8145", "8146"); # $SSLPorts-functionallity Added 2025-05-04 /JOHHO
# $PSScriptRoot = Split-Path -Parent $($MyInvocation.MyCommand.Path); # JOHHO/ verified issue with Path: $($MyInvocation.MyCommand.Path)
# $PSScriptRoot = (Get-Location).path; # 2025-05-04 /JOHHO
$Paths = @("C:\itm8", "C:\ITR", "$([Environment]::GetFolderPath("Desktop"))"); # 2025-05-06 /JOHHO
$ScriptTerminationSleep = 30;
#
### Script
$MyInvocation.MyCommand.name
$SupportedOS = IF (!((((Get-WmiObject -class Win32_OperatingSystem).Caption) -notlike "*Server 2016*") -and ((([Environment]::OSVersion).version) -ge [Version]‘10.0.0.0’) )) {
  Write-Host "`n  Os is not supported to run from Github!`n  -- Run a local version of this script --`n`n  Script will terminate!`n";
  Sleep $ScriptTerminationSleep;
  Break;};

$ThisDomain = $null
Foreach ($Path in $Paths) { # Verify and create Folder: Cert-Reports
  If (Test-Path $Path) {
    If (!(Test-Path "$($Path)\Cert-Reports")){ New-Item -Path "$($Path)\Cert-Reports" -ItemType Directory -force | Out-Null; };
    $PSScriptRoot = "$($Path)\Cert-Reports";
    Break;
  };
};
## Functions
Function Lookup-SSLCerts {
  param ($fDomains, $fThisDomain, $fSSLPorts)
  $Timer01 = [System.Diagnostics.Stopwatch]::StartNew() #TIMER
  $results = {};
  Write-Host "`n  Starting SSLCert-lookup for: $(($fDomains).count) DNS-Records/Domains`n";
  ForEach ($Domain in $fDomains) { # 2025-05-04 /JOHHO
    [Array]$ArgumentList = @($Domain, $fThisDomain, $fSSLPorts)
    $ScriptBlock11 = {
      param ($Domain, $ThisDomain, $SSLPorts)
      $DisplayAllInfo = $false;
	  #$DisplayAllInfo = $true;
      IF ($DisplayAllInfo -eq $true) {Write-Host "`n  HostName:   $($Domain.Hostname)";}
      IF ($DisplayAllInfo -eq $true) {Write-Host "  ThisDomain: $($ThisDomain)";}
      ## ScriptBlock Functions
      Function Test-Port {
          [CmdletBinding()]
          param (
              [Parameter(ValueFromPipeline = $true, HelpMessage = 'Could be suffixed by :Port')]
              [String[]]$ComputerName,
      
              [Parameter(HelpMessage = 'Will be ignored if the port is given in the param ComputerName')]
              [Int]$Port = 5985,
      
              [Parameter(HelpMessage = 'Timeout in millisecond. Increase the value if you want to test Internet resources.')]
              [Int]$Timeout = 1000
          )
          begin {
              $result = [System.Collections.ArrayList]::new()
          }
          process {
              foreach ($originalComputerName in $ComputerName) {
                  $remoteInfo = $originalComputerName.Split(":")
                  if ($remoteInfo.count -eq 1) {
                      # In case $ComputerName in the form of 'host'
                      $remoteHostname = $originalComputerName
                      $remotePort = $Port
                  } elseif ($remoteInfo.count -eq 2) {
                      # In case $ComputerName in the form of 'host:port',
                      # we often get host and port to check in this form.
                      $remoteHostname = $remoteInfo[0]
                      $remotePort = $remoteInfo[1]
                  } else {
                      $msg = "Got unknown format for the parameter ComputerName: " `
                          + "[$originalComputerName]. " `
                          + "The allowed formats is [hostname] or [hostname:port]."
                      Write-Error $msg
                      return
                  }
                  $tcpClient = New-Object System.Net.Sockets.TcpClient
                  $portOpened = $tcpClient.ConnectAsync($remoteHostname, $remotePort).Wait($Timeout)
      
                  $null = $result.Add([PSCustomObject]@{
                      RemoteHostname       = $remoteHostname
                      RemotePort           = $remotePort
                      PortOpened           = $portOpened
                      TimeoutInMillisecond = $Timeout
                      SourceHostname       = $env:COMPUTERNAME
                      OriginalComputerName = $originalComputerName
                      })
              }
          }
          end {
              return $result
          }
      }; # END Function Test-Port
      function Test-TCPConnectionAsync {
          [cmdletbinding()]
          param(
              [parameter(Mandatory, Valuefrompipeline, ValueFromPipelineByPropertyName)]
              [alias('Target', 'HostName', 'Host')]
              [string[]] $ComputerName,
      
              [parameter(ValueFromPipelineByPropertyName)]
              [ValidateRange(1, 65535)]
              [int[]] $Port = 443,
      
              [parameter(ValueFromPipelineByPropertyName)]
              [string[]] $ExpectedIP,
      
              [parameter()]
              [ValidateRange(100, [int]::MaxValue)]
              [int] $TimeOut = 1000 # In miliseconds!
          )
          begin {
            IF ($DisplayAllInfo -eq $true) {Write-Host "  -- Testing DNS and Port: $($ComputerName):$($Port)";}; # /JOHHO
              $fTimer01 = [System.Diagnostics.Stopwatch]::StartNew()
              $queue = [System.Collections.Generic.List[hashtable]]::new() #[List[hashtable]]::new()
              #$TimeOut = [timespan]::FromSeconds($TimeOut).TotalMilliseconds
              $ProtocolNames = [System.Security.Authentication.SslProtocols] | Get-Member -Static -MemberType Property | Where-Object { $_.Name -notin @("Default", "None") } | ForEach-Object { $_.Name }
              $ProtocolStatus = [Ordered]@{}
              $ProtocolStatus.Add("ComputerName", $ComputerName)
              $ProtocolStatus.Add("ExpectedIP", "$ExpectedIP")
              $ProtocolStatus.Add("Port", $Port)
              $ProtocolStatus.Add("Valid", $false)
              $PowershellVersion = $PSVersionTable.PSVersion.Major
              $idnMapping = New-Object System.Globalization.IdnMapping
          } process {
              #$ProtocolStatus.Add("Valid", $false)
              if (((Test-Port $($ComputerName) $($Port)).PortOpened) -eq $true) { 
              #if ((TestTCP -address "$ComputerName" -timeout $TimeOut) -eq $true) {
                  # write-host "$ComputerName success!"
                  $ProtocolStatus['Response'] = $true
                  $OSversion = [Environment]::OSVersion.Version.build
              
                  $ProtocolNames | ForEach-Object {
                      $ProtocolName = $_
                      #$ComputerName
                      #$ComputerName = 'edellroot.badssl.com' #"google.dk"
                      #$Port = 443
                      Write-Verbose "Test-TCPConnectionAsync: Testing $ProtocolName $($ComputerName):$Port"
                      #$Socket.Connect('nogetnice.dk', 443)
                      $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                      $Socket.Connect("$ComputerName", "$Port")
                      $Socket.ReceiveTimeout = 1000
                      if ($Socket.RemoteEndPoint.Address.IsIPv4MappedToIPv6 -eq $true) {
                          $ProtocolStatus["ResolvedIPAddress"] = $Socket.RemoteEndPoint.Address.MapToIPv4().IPAddressToString
                      } else {
                          $ProtocolStatus["ResolvedIPAddress"] = $Socket.RemoteEndPoint.Address.IPAddressToString
                      }
                      try {
                          if ($ProtocolStatus["ResolvedIPAddress"] -ne '' -and $null -ne $ProtocolStatus["ResolvedIPAddress"]) {
                              Write-Verbose "Test-TCPConnectionAsync: Trying to do $($ProtocolStatus["ResolvedIPAddress"]) on  $ProtocolName $($ComputerName):$Port"
                              $PTR = ((nslookup $ProtocolStatus["ResolvedIPAddress"] 2> $null | Select-String -Pattern "Name:") -Split ":") #Resolve-DnsName PTR is somehow ultra slow on some machines
                              if ($PTR) {
                                  $ProtocolStatus["ResolvedPTRAddress"] = $PTR[1].trim()
                              }
                              Write-Verbose "Test-TCPConnectionAsync: nslookup $($ProtocolStatus["ResolvedIPAddress"]) completed on  $ProtocolName $($ComputerName):$Port"
                          }
                      } catch {
                          $ProtocolStatus["ResolvedPTRAddress"] = ''
                      }
                      #$Socket = (New-Object System.Net.Sockets.TcpClient).Connect($ComputerName, $Port).Wait(1000)
                      try {
                          $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                          $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true, { $true })
                          $SslStream.AuthenticateAsClient($ComputerName, $null, $ProtocolName, $false )
                          $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                          
                          #$ProtocolStatus["debug"] = $SslStream.DnsNameList
                          $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.SignatureAlgorithm.FriendlyName
                          #$ProtocolStatus["Certificate"] = $RemoteCertificate
                          $ProtocolStatus["Thumbprint"] = $RemoteCertificate.Thumbprint
                          $ProtocolStatus["SubjectName"] = $RemoteCertificate.SubjectName.Name
                          $ProtocolStatus["IssuerName"] = $RemoteCertificate.IssuerName.Name
                          $ProtocolStatus["NotBefore"] = $RemoteCertificate.NotBefore
                          $ProtocolStatus["NotAfter"] = $RemoteCertificate.NotAfter
                          $ProtocolStatus["ExpireInDays"] = (New-TimeSpan -Start $(Get-Date) -End $RemoteCertificate.NotAfter).days
                          $ProtocolStatus["SubjectAlternativeName"] = $RemoteCertificate.DnsNameList.Punycode
                          $ProtocolStatus["Verify"] = $RemoteCertificate.Verify()
                          if ($PowershellVersion -eq 7) {
                              $ProtocolStatus["MatchesHostname"] = $RemoteCertificate.MatchesHostname("$ComputerName")
                          } else {
                              $ProtocolStatus["MatchesHostname"] = $false
                              foreach ($DnsName in $RemoteCertificate.DnsNameList.Punycode) {
                                  if ($idnMapping.GetAscii("$ComputerName") -match "^$DnsName$") {
                                      $ProtocolStatus["MatchesHostname"] = $true
                                  }
                              }
                          }
                          $ProtocolStatus["$ProtocolName"] = $true
                      } catch {
                          if ($ProtocolName -eq "Tls13" -and ($OSversion -lt 20300)) {
                              $ProtocolStatus.Add($ProtocolName, "Unsupported")
                          } elseif ($ProtocolName -eq "Tls12" -and ($OSversion -lt 9600)) {
                              $ProtocolStatus.Add($ProtocolName, "Unsupported")
                          } else {
                              $ProtocolStatus.Add($ProtocolName, $false)
                          }
                      } finally {
                          $SslStream.Close()
                      }
                  }
                  if ($ProtocolStatus["Verify"] -eq $true -and $ProtocolStatus["MatchesHostname"] -eq $true) {
                      $ProtocolStatus["Valid"] = $true
                  }
              } else {
                  Write-Verbose "Test-TCPConnectionAsync: Trying to do forward lookup on  $ProtocolName $($ComputerName):$Port"
                  if ((nslookup "$ComputerName" 2> $null | Out-String) -match '(?s)Name:.*?Address:\s*(\d+\.\d+\.\d+\.\d+)') {
                      $ProtocolStatus["ResolvedIPAddress"] = $matches[1]
                      try {
                          if ($ProtocolStatus["ResolvedIPAddress"] -ne '' -and $null -ne $ProtocolStatus["ResolvedIPAddress"]) {
                              Write-Verbose "Test-TCPConnectionAsync: Trying to do $($ProtocolStatus["ResolvedIPAddress"]) on  $ProtocolName $($ComputerName):$Port"
                              $PTR = ((nslookup $ProtocolStatus["ResolvedIPAddress"] 2> $null | Select-String -Pattern "Name:") -Split ":") #Resolve-DnsName PTR is somehow ultra slow on some machines
                              if ($PTR) {
                                  $ProtocolStatus["ResolvedPTRAddress"] = $PTR[1].trim()
                              }
                              Write-Verbose "Test-TCPConnectionAsync: nslookup $($ProtocolStatus["ResolvedIPAddress"]) completed on  $ProtocolName $($ComputerName):$Port"
                          }
                      } catch {
                          $ProtocolStatus["ResolvedPTRAddress"] = ''
                      }
                  }
                  $ProtocolStatus['Response'] = $false
              }
              [PSCustomObject]$ProtocolStatus
          }
          ###
          end {
              while ($queue -and $fTimer01.ElapsedMilliseconds -le $timeout) {
                  try {
                      $id = [Task]::WaitAny($queue.Task, 200)
                      if ($id -eq -1) {
                          continue
                      }
                      $instance, $task, $output = $queue[$id]['Instance', 'Task', 'Output']
                      if ($instance) {
                          $instance.Dispose()
                      }
                      $output['Success'] = $task.Status -eq [TaskStatus]::RanToCompletion
                      $queue.RemoveAt($id)
                      [pscustomobject] $output
                  } catch {
                      $_
                      #$PSCmdlet.WriteError($_)
                  }
              };
              foreach ($item in $queue) {
                  try {
                      $instance, $task, $output = $item['Instance', 'Task', 'Output']
                      $output['Success'] = $task.Status -eq [TaskStatus]::RanToCompletion
                      if ($instance) {
                          $instance.Dispose()
                      }
                      [pscustomobject] $output
                      
                  } catch {
                      $PSCmdlet.WriteError($_)
                  }
              };
          };
      }; # END Test-TCPConnectionAsync
      ## End Functions
    
      if (($Domain.Hostname).EndsWith($ThisDomain.ToLower()) -or (($Domain.Hostname).EndsWith($ThisDomain.ToLower() + "."))) {
        $Domain.Hostname = $Domain.Hostname -replace '\.$', ''
      } elseif ($Domain.Hostname -eq "@") {
        $Domain.Hostname = $ThisDomain
      }
      else {
        $Domain.Hostname = "$($Domain.Hostname).$ThisDomain"
      }
      if (($Domain.Hostname).StartsWith(("`*"))) {
        $Domain.Hostname = "ANY." + ($Domain.Hostname).Replace('*.', '')
      }
      $Openports = ForEach ($Port in $SSLPorts) {if ((($result = (Test-Port $($Domain.Hostname) $Port)).PortOpened) -eq $true) {$result.RemotePort}};
      IF ($DisplayAllInfo -eq $true) {Write-Host "  Open Ports: $($Openports)"; }
      $ReturnResult = ForEach ($Port in $Openports) {Test-TCPConnectionAsync -Target $Domain.Hostname -ExpectedIP $Domain.IP -Port $Port -TimeOut 500};
      return $ReturnResult;
    } 
    $JobResult = Start-Job -Scriptblock $ScriptBlock11 -ArgumentList $ArgumentList -Name "LookUpDomain_$($Domain.Hostname)";
	IF ($DisplayAllInfo -eq $true) {$Jobs = Get-Job -Name "LookUpDomain_*"; Write-Host "Jobs Running: $(($Jobs  | ? {($_.State -eq "Running")}).count) - Completed: $(($Jobs  | ? {($_.State -eq "Completed")}).count) - Failed: $(($Jobs  | ? {($_.State -eq "Failed")}).count)";};
    $ThrottleLimit = 15; While (((Get-Job -Name "LookUpDomain_*" | ? {($_.State -eq "Running")}).count) -ge $ThrottleLimit ){Start-Sleep 1; }; # Thread Throttleling function - $ThrottleLimit NOT above 16 / JOHHO

  }
  
  Show-JobStatus "LookUpDomain_";
  $fResults = Foreach ($fJob in (Get-Job -Name "LookUpDomain_*")) {Receive-Job -id $fJob.ID -Keep}; Get-Job -State Completed | Remove-Job;
  
  $Timer01.Stop();
  Write-Host "`n  Elapsed time for Function Lookup-SSLCerts: $($Timer01.Elapsed)`n";
  # Return Data
  Return $fResults
}; # END Function Lookup-SSLCerts
Function Show-JobStatus { Param ($fJobNamePrefix)
  # Add this line to Script: Show-JobStatus $fJobNamePrefix;
  DO { IF ((Get-Job -Name "$($fJobNamePrefix)*").count -ge 1) {$fStatus = ((Get-Job -State Completed).count/(Get-Job -Name "$($fJobNamePrefix)*").count) * 100;
    Write-Progress -Activity "Waiting for $((Get-Job -State Running).count) of $((Get-Job -Name "$($fJobNamePrefix)*").count) job(s) to complete..." -Status "$($fStatus) % completed" -PercentComplete $fStatus; }; }
  While ((Get-job -Name "$($fJobNamePrefix)*" | Where State -eq Running));
};
## END Functions

try { # Try-Catch - Verify if DNS-Service is installed
  if ((get-windowsfeature -Name DNS).Installed -eq $true) {
    # Load the necessary assembly for Windows Forms
    Add-Type -AssemblyName System.Windows.Forms

    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Load Zonefile"
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.StartPosition = "CenterScreen"

    # Create the first button
    $button1 = New-Object System.Windows.Forms.Button
    $button1.Text = "Windows DNS Server"
    $button1.Size = New-Object System.Drawing.Size(100, 50)
    $button1.Location = New-Object System.Drawing.Point(50, 50)

    # Create the second button
    $button2 = New-Object System.Windows.Forms.Button
    $button2.Text = "File Browser"
    $button2.Size = New-Object System.Drawing.Size(100, 50)
    $button2.Location = New-Object System.Drawing.Point(150, 50)

    # Define the event handler for the first button
    $button1.Add_Click({
      $global:option = 1
        [void]$form.Close(); [void]$form.Dispose();
    })

    # Define the event handler for the second button
    $button2.Add_Click({
      $global:option = 2
        [void]$form.Close(); [void]$form.Dispose();
    })

    # Add the buttons to the form
    $form.Controls.Add($button1)
    $form.Controls.Add($button2)

    # Show the form
    $form.Add_Shown({$form.Activate()})
    [System.Windows.Forms.Application]::Run($form)
  } else { $global:option = 2}
} catch {
  $global:option = 2
}; # END Try-Catch - Verify if DNS-Service is installed

if ($global:option -eq 1) {
  # Create a new form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Windows DNS Server"
  $form.Size = New-Object System.Drawing.Size(300, 250)
  $form.StartPosition = "CenterScreen"

  # Create a ListBox
  $listBox = New-Object System.Windows.Forms.ListBox
  $listBox.Size = New-Object System.Drawing.Size(260, 140)
  $listBox.Location = New-Object System.Drawing.Point(10, 10)

  # Add items to the ListBox
  $listBox.Items.AddRange((Get-DnsServerZone | Where-Object{ $_.ZoneName -notlike "*in-addr.arpa"} | Select-Object -ExpandProperty ZoneName))

  # Add the ListBox to the form
  $form.Controls.Add($listBox)

  # Create a button to show the selected item
  $button = New-Object System.Windows.Forms.Button
  $button.Text = "Load DNS Zone"
  $button.Location = New-Object System.Drawing.Point(10, 140)
  $button.Size = New-Object System.Drawing.Size(260, 30)

  # Add a click event to the button
  $button.Add_Click({
      Get-DnsServerResourceRecord -ZoneName $($listBox.SelectedItem) | Out-File "$PSScriptRoot\tempzone.txt"
      $global:dnsZoneContent = Get-Content "$PSScriptRoot\tempzone.txt"
      Remove-Item "$PSScriptRoot\tempzone.txt"
      $global:AutoValue = $($listBox.SelectedItem)
      [void]$form.Close(); [void]$form.Dispose();
  })

  # Add the button to the form
  $form.Controls.Add($button)

  # Show the form
  $form.Add_Shown({$form.Activate()})
  [void]$form.ShowDialog()
} elseif ($global:option -eq 2) {
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
      InitialDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')
      Filter           = 'DNS files (*.*)|*.txt;*.DNS|All files (*.*)|*.*'
    }
    $null = $FileBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
    if (-not $FileBrowser.FileName) {
      exit
    }
    $global:dnsZoneContent = Get-Content $FileBrowser.FileName
}
#Write-Host "`n  Imported DNS Records:"; 
#$global:dnsZoneContent
$dnsZoneContentFirst10 = $global:dnsZoneContent | Select-Object -First 10 

if (($dnsZoneContentFirst10 | Select-String -Pattern "Domain:") -match ';; Domain:\s*(?<Domain>[^\s]+)') {
  $global:AutoValue = ($matches['Domain']).TrimEnd(".")
} elseif (($dnsZoneContentFirst10 | Select-String -Pattern '\$ORIGIN') -match '\$ORIGIN\s+(?<Origin>[^\s]+)') {
  $global:AutoValue = ($matches['Origin']).TrimEnd(".")
} elseif (!($global:AutoValue)) {
  $global:AutoValue = (Get-ChildItem $FileBrowser.FileName).BaseName
}

#Confirm domain name
$form = New-Object Windows.Forms.Form
$form.Text = "Domain Name"
$form.Size = New-Object Drawing.Size(300, 150)
$textBox = New-Object Windows.Forms.TextBox
$textBox.Location = New-Object Drawing.Point(20, 20)
$textBox.Size = New-Object Drawing.Size(200, 20)
$textBox.Text = $AutoValue
$form.Controls.Add($textBox)
$button = New-Object Windows.Forms.Button
$button.Text = "Confirm"
$button.Location = New-Object Drawing.Point(20, 60)
$button.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($button)

$res = $form.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))

if ($res -eq 'OK') {
  $ThisDomain = $textBox.Text
}

if (-not $ThisDomain) {
  Write-Host "`n  No Domain-selection registered!`n`n  Script will terminate!`n";
  Sleep $ScriptTerminationSleep;
  Break
}
$Domains = @()
$dnsZoneContentParsed = @()
if (($dnsZoneContentFirst10 | Out-String) -match '^A\s+Host:\s+') {
  $pattern = 'A\s+Host:\s+(?<Hostname>\S+)\s+TTL:\s+\S+\s+IPv4:\s+(?<IPv4>\d+\.\d+\.\d+\.\d+)'
  $matches = [regex]::Matches(($global:dnsZoneContent | Out-String), $pattern)
  foreach ($match in $matches) {
    $Domains += [pscustomobject]@{
      Hostname = $match.Groups['Hostname'].Value
      IP       = $match.Groups['IPv4'].Value
    }
  }
} else {
  $pattern = '(?=.*\sA\s.*|.*\sA$)^(?!;)([^\s]+).*\s?(\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b)'
  ForEach ($line in $global:dnsZoneContent) {
    if ($line -match $pattern) {
      #$matches[0]
      $Domains += [pscustomobject]@{
        Hostname   = $matches[1]
        IP         = $matches[2]
      }
      $dnsZoneContentParsed += [pscustomobject]@{Line = $line + " ;; Matched as A-record by SSL Scan." }
    }
    else {
      $dnsZoneContentParsed += [pscustomobject]@{Line = $line }
    }
  }
}
#write-host "`n  Domains:"
#$Domains
if (-not $Domains) {
  Write-Host "`n  No DNS-Records/Domains registered!`n`n  Script will terminate!`n";
  Sleep $ScriptTerminationSleep;
  Break;
}

## Lookup-SSLCerts
$results = Lookup-SSLCerts -fDomain $Domains -fThisDomain $ThisDomain -fSSLPorts $SSLPorts

# 2025-03-31 /JOHHO: $formattetResult = $results| Select-Object ExpectedIP, ResolvedIPAddress, ResolvedPTRAddress, @{Name = "Hostname"; Expression = { $_.ComputerName } }, @{Name = "Port"; Expression = { $_.Port } }, Valid, Response, SignatureAlgorithm, Thumbprint, SubjectName, @{Name = "SubjectAlternativeName"; Expression = { ($_.SubjectAlternativeName) } }, IssuerName, NotBefore, NotAfter, ExpireInDays, Verify, MatchesHostname, Ssl2, Ssl3, tls, Tls11, Tls12, Tls13
$formattetResult = $results | Sort ComputerName -Descending | Select-Object @{Name = "Hostname"; Expression = { $_.ComputerName } }, ExpectedIP, ResolvedIPAddress, ResolvedPTRAddress, @{Name = "Port"; Expression = { $_.Port } }, Valid, Response, SignatureAlgorithm, Thumbprint, SubjectName, @{Name = "SubjectAlternativeName"; Expression = { ($_.SubjectAlternativeName) } }, IssuerName, NotBefore, @{Name = "ExpireDate"; Expression = { $_.NotAfter } }, ExpireInDays, Verify, MatchesHostname, Ssl2, Ssl3, tls, Tls11, Tls12, Tls13

$ReportName = "$($ThisDomain)_$(Get-Date -f yyyy-MM-dd-HHmmss)"

# $formattetResult | Export-Csv -Delimiter ";" -Path "$PSScriptRoot\Reports\$ReportName.csv"
$formattetResult | Export-Csv -Delimiter ";" -Path "$PSScriptRoot\$ReportName.csv"; # 2025-05-07 /JOHHO

#HTML REPORT GENERATION
$DNSservers = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
$ErrorActionPreference = "SilentlyContinue";
$DNSserversPrimary = ((nslookup $DNSservers[0] 2> $null | Select-String -Pattern "Name:") -Split ":")[1].trim()# Resolve-DnsName does not play nice with PTR addresses
$DNSserversSecondary = ((nslookup $DNSservers[1] 2> $null | Select-String -Pattern "Name:") -Split ":")[1].trim()# Resolve-DnsName does not play nice with PTR addresses
$ErrorActionPreference = "Continue";

#Ugly TLS support check, with fallback to known values if online check fails. Purpose is to support 3rd party patched compatibility. 
$OSversion = [Environment]::OSVersion.Version.build

$TLStester = (Invoke-WebRequest "https://check.tls.support/" | ConvertFrom-Json).tls_version
if ($TLStester) {
  switch ($TLStester) {
    "TLS 1.0" { $OSversion = 6003 }
    "TLS 1.1" { $OSversion = 7601 }
    "TLS 1.2" { $OSversion = 9600 }
    "TLS 1.3" { $OSversion = 20300 }
    Default { $OSversion = $OSversion }
  }
}

$TLSversionSupport = [ordered]@{
  'tls10' = ($OSversion -ge 6003)
  'tls11' = ($OSversion -ge 7601)
  'tls12' = ($OSversion -ge 9600)
  'tls13' = ($OSversion -ge 20300)
}

#HTML header
$header = @"
<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js" integrity="sha384-+sLIOodYLS7CIrQpBjl+C7nPvqq+FbNUBDunl/OZv93DB7Ln/533i8e/mZXLi/P+" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@3.1/dist/js/adminlte.min.js" integrity="sha384-M2jy5xB5VAgRZKkRV4aK+csQ0HDF0CaDlqlEet4fxrIX5vWu771VxrpBbOVolVAY" crossorigin="anonymous"></script>
<script src="https://cdn.datatables.net/2.2.2/js/dataTables.min.js" integrity="sha384-AenwROccLjIcbIsJuEZmrLlBzwrhvO94q+wm9RwETq4Kkqv9npFR2qbpdMhsehX3" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.1.6/Chart.js" integrity="sha512-cUN0myk0UGEvxqLxibWVur2Ax3f2cznXn78AMoe6Hj2lIXD5+dvoKGwLeNzlLE2Jk2+VfyX/tEfvIZmieMSt1w==" crossorigin="anonymous"></script>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@3.1/dist/css/adminlte.min.css">
<link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css" />

<script>
  document.addEventListener("DOMContentLoaded", function(event){
    function extractOrganization(input) {
      const match = input.match(/O=([^,]+)(?:,|$)/);
      return match ? match[1] : null;
    }
    function extractName(input) {
      const match = input.match(/CN=([^,]+)(?:,|$)/);
      return match ? match[1] : null;
    }  

    var table = document.getElementById('table1');
    var firstRow = table.getElementsByTagName('tr')[0];
    var thead = document.createElement('thead');
    thead.appendChild(firstRow);
    table.insertBefore(thead, table.firstChild);
    `$('td:nth-child(7):contains("False")').parent().addClass("disabled")
    `$('td:nth-child(6):contains("False")').parent().addClass("notvalid")
      let input = `$('td:nth-child(15)')
      input.each(function() {
          if (!!`$( this ).text()) {
            if (`$( this ).text() < 0) {
              `$( this ).parent().addClass("danger")
            } else if (`$( this ).text() < 30) {
              `$( this ).parent().addClass("warning")
            }
          }  
      });
    let tableAll = new DataTable('#table1', {
      order: [[5, 'desc']],
      paging: false
    });
    const originalTable = document.getElementById('table1');
    const rows = originalTable.querySelectorAll('tbody tr');
    var stats = {
      TotalLookups : 0,
      ssl2 : 0,
      ssl3 : 0,
      tls10 : 0,
      tls11 : 0,
      tls12 : 0,
      tls13 : 0,
      unsupported : 0,
      validCerts : 0,
      response : 0,
      issuerCount : {}
    }

      // Object to store rows grouped by ID
    const groupedRows = {};

    // Iterate through rows and group by ID
    rows.forEach(row => {
        stats['TotalLookups']++
        if (row.cells[17].textContent == "True") {
          stats['ssl2']++
        }
        if (row.cells[18].textContent == "True") {
          stats['ssl3']++
        }
        if (row.cells[19].textContent == "True") {
          stats['tls10']++
        }
        if (row.cells[20].textContent == "True") {
          stats['tls11']++
        }
        if (row.cells[21].textContent == "True") {
          stats['tls12']++
        }
        if (row.cells[22].textContent == "True") {
          stats['tls13']++
        }
        if (row.cells[6].textContent == "True") {
          stats['response']++
        }
        if (row.cells[6].textContent == "True" && row.cells[17].textContent != "True" && row.cells[18].textContent != "True" && row.cells[19].textContent != "True" && row.cells[20].textContent != "True" && row.cells[21].textContent != "True" && row.cells[22].textContent != "True") {
          stats['unsupported']++
        }
        if ((row.cells[6].textContent == "True") && (row.cells[5].textContent == "True")) {
          stats['validCerts']++
        }
        if (row.cells[11].textContent != "") {
        }

        const id = row.cells[8].textContent; 
        if (!!id) {
          if (!groupedRows[id]) {
              groupedRows[id] = []; 

                 if (stats['issuerCount'][extractOrganization(row.cells[11].textContent)]) {
                  stats['issuerCount'][extractOrganization(row.cells[11].textContent)]++
                } else {
                  stats['issuerCount'][extractOrganization(row.cells[11].textContent)] = 1
                }
          }
          groupedRows[id].push(row); 
        }
    });
    console.log(stats)

    function addData(chart, label, data) {
      chart.data.labels.push(label);
      chart.data.datasets.forEach((dataset) => {
          dataset.data.push(data);
      });
      chart.update();
    }

    const TlsChart = document.getElementById('TlsChart');
    const TlsChartGraphic  = new Chart(TlsChart, {
        type: 'doughnut',
        data: {
            labels: ['SSL2','SSL3','TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3', 'Unsupported'],
            datasets: [{
                data: [stats.ssl2,stats.ssl3,stats.tls10, stats.tls11, stats.tls12, stats.tls13, stats.unsupported],
                backgroundColor: [
                    'rgb(255, 0, 0)',
                    'rgb(255, 60, 0)',
                    'rgb(255, 122, 99)',
                    'rgb(255, 151, 55)',
                    'rgb(180, 255, 59)',
                    'rgb(87, 255, 53)',
                ]
            }]
        },
        options: {
            responsive: false,
            legend: false,
            autoPadding: false
        }
    });

    const OrganizaitionChart = document.getElementById('OrganizaitionChart');
    const OrganizaitionChartGraphic = new Chart(OrganizaitionChart, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgb(73, 137, 255)',
                    'rgb(255, 253, 145)',
                    'rgb(255, 122, 99)',
                    'rgb(55, 208, 255)',
                    'rgb(180, 255, 59)',
                    'rgb(236, 159, 255)',
                    'rgb(63, 217, 255)',
                    'rgb(255, 205, 40)',
                    'rgb(100, 255, 79)',
                ]
            }]
        },
        options: {
            responsive: false,
            legend: false,
            autoPadding: false
        }
    });

    Object.entries(stats.issuerCount).forEach(([key, value]) => {
      addData(OrganizaitionChartGraphic, key, value)
    });

        const organizationsTable = document.createElement('table');
        organizationsTable.classList.add('table', 'hover', 'nowrap', 'cell-border');

        // Create the table header
        const headerRow = document.createElement('tr');
        const headers = ["Issuer", "Unique Certificates"];
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        organizationsTable.appendChild(headerRow);

        
        // Convert issuerCount to an array of [issuer, count] pairs
        const issuerCountArray = Object.entries(stats.issuerCount);

        // Sort the array by count in descending order
        issuerCountArray.sort((a, b) => b[1] - a[1]);

        // Calculate the sum of counts
        let totalCount = 0;

        // Create table rows from issuerCount
        issuerCountArray.forEach(([issuer, count]) => {
            const row = document.createElement('tr');

            const issuerCell = document.createElement('td');
            issuerCell.textContent = issuer;
            row.appendChild(issuerCell);

            const countCell = document.createElement('td');
            countCell.textContent = count;
            row.appendChild(countCell);

            organizationsTable.appendChild(row);

            // Add to the total count
            totalCount++;
        });

        // Add a total row
        const totalRow = document.createElement('p');
        totalRow.classList.add('total-row'); // Add a class for styling

        totalRow.textContent = "Total Issuers: " + totalCount;

        // Append the table to the container
        const tableContainer = document.getElementById('organizationsTableContainer');
        tableContainer.appendChild(organizationsTable);
        tableContainer.appendChild(totalRow);

    const ResponseChart = document.getElementById('ResponseChart');
    const NoResponse = (stats.TotalLookups - stats.response)
    const ResponseChartChartGraphic = new Chart(ResponseChart, {
        type: 'doughnut',
        data: {
            labels: ["Response","No response"],
            datasets: [{
                data: [stats.response,NoResponse],
                backgroundColor: [
                    'rgb(83, 255, 3)',
                    'rgb(255, 0, 0)',
                ]
            }]
        },
        options: {
            responsive: false,
            legend: false,
            autoPadding: false
        }
    });

    // Get the container for new tables
    const tablesContainer = document.getElementById('tablesContainer');

    /*
    // Get the container for new tables
    const tablesContainer = document.getElementById('tablesContainer');

    // Create a new table for each unique ID
    for (const id in groupedRows) {
        // Create a new table element
        const newTable = document.createElement('table');
        
        newTable.setAttribute('border', '1');
        newTable.setAttribute('class', 'table hover nowrap cell-border');
        newTable.setAttribute('data-thumbprint', id);

        // Create a header for the new table
        const header = document.createElement('thead');
        const headerRow = document.createElement('tr');
        originalTable.querySelectorAll('th').forEach(th => {
            const newTh = document.createElement('th');
            newTh.textContent = th.textContent;
            headerRow.appendChild(newTh);
        });
        header.appendChild(headerRow);
        newTable.appendChild(header);

        // Create a body for the new table
        const body = document.createElement('tbody');
        groupedRows[id].forEach((row, index) => {
            const newRow = document.createElement('tr');
             
            newRow.className = row.className;

            if (index === 0) {
              newTable.setAttribute('data-expiredays', row.cells[14].textContent);
              newTable.setAttribute('data-subjectname', row.cells[9].textContent);
            }
            row.querySelectorAll('td').forEach(td => {
                const newTd = document.createElement('td');
                newTd.textContent = td.textContent;
                newRow.appendChild(newTd);
            });
            body.appendChild(newRow);
        });
        newTable.appendChild(body);

        // Add the new table to the container
        tablesContainer.appendChild(newTable);
    }
    */

    // Create an array to hold the tables
let tablesArray = [];

for (const id in groupedRows) {
    // Create the card container for each table
    const cardDiv = document.createElement('div');
    cardDiv.classList.add('card', 'shadow', 'collapsed-card');
    //cardDiv.style = "background-color: #6d20a3; color:white;"

    // Create the card header
    const cardHeader = document.createElement('div');
    cardHeader.classList.add('card-header');
    cardHeader.setAttribute('data-card-widget', 'collapse');
    const headerTitle = document.createElement('h3');
    headerTitle.classList.add('card-title');
    headerTitle.style = "font-weight: 700;"
    
    cardHeader.appendChild(headerTitle);

    const cardTools = document.createElement('div');
    cardTools.classList.add('card-tools');
    const closeButton = document.createElement('button');
    closeButton.setAttribute('type', 'button');
    closeButton.classList.add('btn', 'btn-tool');
    closeButton.innerHTML = 'Details';
    cardTools.appendChild(closeButton);

    cardHeader.appendChild(cardTools);
    cardDiv.appendChild(cardHeader);

    // Create the card body
    const cardBody = document.createElement('div');
    cardBody.classList.add('card-body');

    // Create a new table element
    const newTable = document.createElement('table');
    newTable.setAttribute('border', '1');
    newTable.setAttribute('class', 'table hover nowrap cell-border');
    newTable.setAttribute('data-thumbprint', id);

    // Create a header for the new table
    const header = document.createElement('thead');
    const headerRow = document.createElement('tr');
    originalTable.querySelectorAll('th').forEach(th => {
        const newTh = document.createElement('th');
        newTh.textContent = th.textContent;
        headerRow.appendChild(newTh);
    });
    header.appendChild(headerRow);
    newTable.appendChild(header);

    // Create a body for the new table
    const body = document.createElement('tbody');
    groupedRows[id].forEach((row, index) => {
        const newRow = document.createElement('tr');
        newRow.className = row.className;

        if (index === 0) {
            // Set the data-expiredays from the first row's 14th cell
            const expiredays = row.cells[14].textContent;
            newTable.setAttribute('data-expiredays', expiredays);
            newTable.setAttribute('data-subjectname', row.cells[9].textContent);
         
            
            const headerOrganizationSpan = document.createElement('span');
            headerOrganizationSpan.innerHTML = extractOrganization(row.cells[11].textContent);
            headerOrganizationSpan.title = "Issuer Organization"
            headerOrganizationSpan.classList.add('badge');
            headerOrganizationSpan.classList.add('bg-gray');
            cardHeader.appendChild(headerOrganizationSpan);

            var CertValid = row.cells[15].textContent
            const headerValidSpan = document.createElement('span');
            headerValidSpan.classList.add('badge');
            headerValidSpan.title = "Chain Validation"
            if (CertValid == "True") {
              headerValidSpan.innerHTML = "Valid";
              headerValidSpan.classList.add('bg-success');
            } else {
              headerValidSpan.innerHTML = "Invalid";
              headerValidSpan.classList.add('bg-danger');
            }
            cardHeader.appendChild(headerValidSpan);

            const headerExpireSpan = document.createElement('span');
            headerExpireSpan.title = "Days left before expiration"
            headerExpireSpan.innerHTML = expiredays + " days";
            headerExpireSpan.classList.add('badge');
            if (expiredays < 0) {
              headerExpireSpan.classList.add('bg-danger');
            } else if (expiredays < 30) {
              headerExpireSpan.classList.add('bg-warning');
            } else {
              headerExpireSpan.classList.add('bg-success');
            }
            cardHeader.appendChild(headerExpireSpan);

            headerTitle.textContent = extractName(row.cells[9].textContent);
        }
        row.querySelectorAll('td').forEach(td => {
            const newTd = document.createElement('td');
            newTd.textContent = td.textContent;
            newRow.appendChild(newTd);
        });
        body.appendChild(newRow);
    });
    newTable.appendChild(body);

    // Append the table to the card body
    cardBody.appendChild(newTable);

    // Append the card body to the card container
    cardDiv.appendChild(cardBody);

    // Push the card div (with table) and its expiredays into the array
    tablesArray.push({
        table: cardDiv,
        expiredays: parseInt(newTable.getAttribute('data-expiredays'), 10) || 0
    });
}

// Sort the tables by expiredays in ascending order
tablesArray.sort((a, b) => a.expiredays - b.expiredays);

// Append the tables in sorted order
tablesArray.forEach(item => {
    tablesContainer.appendChild(item.table);
});

    const SSLcertificates = document.querySelectorAll('#tablesContainer > table');
    SSLcertificates.forEach(table => {
      let tableAll = new DataTable(table, {
        order: [[5, 'desc']],
        paging: false,
        searching: false,
        info: false
      });
    });
    
    `$('#parsedTable > tbody > tr > td:contains(";; Matched as A-record by SSL Scan.")').addClass('bg-success')
  });

  </script>

<style>
.card-primary.card-outline-tabs>.card-header a.active {
    border-top: 3px solid #6e21a3;
}
table {
    display: block;
    overflow-x: scroll;
    white-space: nowrap;
}
tr.disabled > td {
color: grey;
}
tr.warning > td {
background-color: yellow;
color: black;
}
tr.danger > td {
background-color: red;
color: black;
}
tr:not(.disabled):not(.danger).notvalid > td {
background-color: orange;
color: black;
}
div.card-header > span {
    margin: 3px;
}
.content-wrapper {
    background-color: #ffffff;
}
.total-row {
    font-weight: 700;
}

</style>
"@

#Main table, formattet to HTML and added ID + Classes for styling
$Table = ($formattetResult | ConvertTo-Html -Fragment) -replace '<table>', '<table id="table1" class="table table-hover text-nowrap">'

#Main layout
$layout = @"
<body class="layout-top-nav" style="height: auto;">
<div class="wrapper">

  <!-- Navbar -->
  <nav class="main-header navbar navbar-expand-md navbar-light navbar-white">
    <div class="container">
      <a href="#" class="navbar-brand">
        <img src="https://itm8.dk/hs-fs/hubfs/BRANDING/itm8-rgb-tall.png" class="brand-image" style="padding-top: 8px;">
        <span class="brand-text font-weight-light">SSL scan - $($ThisDomain.ToUpper())</span>
      </a>
      <div class="collapse navbar-collapse order-3" id="navbarCollapse">
        <ul class="order-1 order-md-3 navbar-nav navbar-no-expand ml-auto"><p style="margin-bottom: 0px;" id='CreationDate'>Creation Date: $(Get-Date)</p></ul>
      </div>
    </div>
  </nav>
  <!-- /.navbar -->

  <!-- Content Wrapper. Contains page content -->
  <div class="content-wrapper" style="min-height: 786px;">

    <!-- Main content -->
    <div class="content">
      <div class="container">
        <div class="row" style="margin-top: 2vh;">
          <div class="col-12">
            <div class="card card-primary card-outline card-outline-tabs">
              <div class="card-header p-0 border-bottom-0">
                <ul class="nav nav-tabs" id="custom-tabs-four-tab" role="tablist">
                  <li class="nav-item">
                    <a class="nav-link active" id="custom-tabs-four-home-tab" data-toggle="pill" href="#custom-tabs-four-home" role="tab" aria-controls="custom-tabs-four-home" aria-selected="true">Overview</a>
                  </li>
                  <li class="nav-item">
                    <a class="nav-link" id="custom-tabs-four-settings-tab" data-toggle="pill" href="#custom-tabs-four-settings" role="tab" aria-controls="custom-tabs-four-settings" aria-selected="false">SSL Certificates</a>
                  </li>                  
                  <li class="nav-item">
                    <a class="nav-link" id="custom-tabs-four-profile-tab" data-toggle="pill" href="#custom-tabs-four-profile" role="tab" aria-controls="custom-tabs-four-profile" aria-selected="false">All Lookups</a>
                  </li>
                  <li class="nav-item" style="position: absolute; right: 0px;">
                    <a class="nav-link" id="custom-tabs-four-parsing-tab" data-toggle="pill" href="#custom-tabs-four-parsing" role="tab" aria-controls="custom-tabs-four-parsing" aria-selected="false">Input Data</a>
                  </li>
                </ul>
              </div>
              <div class="card-body">
                <div class="tab-content" id="custom-tabs-four-tabContent">
                  <div class="tab-pane fade active show" id="custom-tabs-four-home" role="tabpanel" aria-labelledby="custom-tabs-four-home-tab">
                  <div class="row">
                    <div class="col-sm-8">
                      <div class="card">
                        <div class="card-header" style="background-color: #6d20a3; color:white;">
                          <h3 class="card-title">Statistics</h3>
                        </div>
                        <div class="card-body">
                          <div id="StatisticsContainer" class="row">
                          <div >
                            <div class="chart col-sm-8 float-left"> 
                              <h3>Response</h3>
                              <p>Chart of port responses.</p>  
                            </div>
                            <div class="chart col-sm-3 float-right" id="ResponseChart-chart" style="width: 100%; height:100%">
                                <canvas id="ResponseChart" width="150" height="150"></canvas>
                            </div>
                          </div>
                          <hr>
                          <div>
                            <div class="chart col-sm-8 float-left"> 
                              <h3>TLS Versions</h3>
                              <p>Chart of TLS version compatibility. Total of all responses shown. <br> Any protocol below TLS 1.2 is seen a insecure.<br> Unsupported protocols are due to incompatibility of protocols or ciphers.</p>  
                            </div>
                            <div class="chart col-sm-3 float-right" id="TlsChart-chart" style="width: 100%; height:100%">
                                <canvas id="TlsChart" width="150" height="150"></canvas>
                            </div>
                          </div>
                          <hr>
                          <div >
                            <div class="chart col-sm-8 float-left"> 
                              <h3>Issuers</h3>
                              <p>Chart of organizations used for issuing SSL certificates.</p>  
                              <div id="organizationsTableContainer"></div>
                            </div>
                            <div class="chart col-sm-3 float-right" id="OrganizationChart-chart" style="width: 100%; height:100%">
                                <canvas id="OrganizaitionChart" width="150" height="150"></canvas>
                            </div>
                          </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div class="col-sm-4">
                      <div class="card card-primary">
                        <div class="card-header" style="background-color: #6d20a3; color:white;">
                          <h3 class="card-title">Generating Machine Info</h3>
                        </div>
                        <div class="card-body">
                         <div class="form-group">
                            <label for="OSversion">Operation System:</label>
                            <input type="text" id="OSversion" class="form-control" value="$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select-Object -ExpandProperty ProductName)" disabled="">
                          </div>
                          <hr>
                          <h6>Supported TLS versions:</h6>
                          <span title="tls1.0" class="badge $(if ($TLSversionSupport.tls10) {"bg-success"} else {"bg-danger"})">TLS1.0</span>
                          <span title="tls1.1" class="badge $(if ($TLSversionSupport.tls11) {"bg-success"} else {"bg-danger"})">TLS1.1</span>
                          <span title="tls1.2" class="badge $(if ($TLSversionSupport.tls12) {"bg-success"} else {"bg-danger"})">TLS1.2</span>
                          <span title="tls1.3" class="badge $(if ($TLSversionSupport.tls13) {"bg-success"} else {"bg-danger"})">TLS1.3</span>

                          $(if ($TLSversionSupport.values -contains $False) {"<div class='alert alert-warning' style='margin-top: 16px;'>The machine generating this report was unable to test all available TLS version(s), as the version(s) are unsupported by the operating system.</div>"})
                          <hr>
                          <div class="form-group">
                            <label for="PrimaryDNS">Primary DNS:</label>
                            <input type="text" id="PrimaryDNS" class="form-control" value="$($DNSservers[0]) $(if ($DNSserversPrimary) {"[$DNSserversPrimary]"})" disabled="">
                          </div>
                          <div class="form-group">
                            <label for="SecondaryDNS">Secondary DNS:</label>
                            <input type="text" id="PrimaryDNS" class="form-control" value="$($DNSservers[1]) $(if ($DNSserversSecondary) {"[$DNSserversSecondary]"})" disabled="">
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>    
                  </div>
                  <div class="tab-pane fade" id="custom-tabs-four-profile" role="tabpanel" aria-labelledby="custom-tabs-four-profile-tab">
                    <div style="padding-bottom: 15px;"> 
                      <span title="SSL Certificate is ready for renewal" class="badge" style="background-color: yellow; color: black;">Less than 30 days</span>
                      <span title="SSL Certificate has expired" class="badge" style="background-color: red; color: black;">Expired</span>
                      <span title="SSL Certificate failed validation" class="badge" style="background-color: orange; color: black;">Not valid</span>
                    </div>  
                     $Table
                  </div>
                  <div class="tab-pane fade" id="custom-tabs-four-settings" role="tabpanel" aria-labelledby="custom-tabs-four-settings-tab">
                     <div id="tablesContainer"></div>
                  </div>
                  <div class="tab-pane fade" id="custom-tabs-four-parsing" role="tabpanel" aria-labelledby="custom-tabs-four-parsing-tab">
                     <div>
                      $(($dnsZoneContentParsed | ConvertTo-Html -Fragment -As List).Replace("<td>*:</td>","").Replace("<hr>","").Replace('<table>', '<table id="parsedTable" class="table text-nowrap">')) 
                     </div>
                  </div>
                </div>
              </div>
              <!-- /.card -->
            </div>
          </div>
        </div>
        <!-- /.row -->
      </div><!-- /.container-fluid -->
    </div>
    <!-- /.content -->
  </div>
  <!-- /.content-wrapper -->

</div>
<!-- ./wrapper -->

"@

#Generate complete report
#$Report | ConvertTo-Html -Body "$layout" -Title "SSL Scanner Report" -Head $header | Out-File -FilePath "$PSScriptRoot\Reports\$($ReportName).html";
$Report | ConvertTo-Html -Body "$layout" -Title "SSL Scanner Report" -Head $header | Out-File -FilePath "$PSScriptRoot\$($ReportName).html"; # 2025-05-07 /JOHHO
Start-Process "$PSScriptRoot\$($ReportName).html"; # 2025-05-07 /JOHHO

#$results | Select-Object ResolvedIPAddress,@{Name="Hostname"; Expression={$_.ComputerName}},@{Name="Port"; Expression={$_.Port}},Valid,Response,SignatureAlgorithm,Thumbprint,SubjectName,SubjectAlternativeName,IssuerName,NotBefore,NotAfter,DnsNameList,Verify,MatchesHostname,tls,Ssl2,Ssl3,Tls11,Tls12,Tls13
