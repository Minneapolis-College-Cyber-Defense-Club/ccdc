$Password = ConvertTo-SecureString -String "P@ssw0rd01" -AsPlainText -Force
$HotWork = New-LocalUser -Name 'HotWork' -Password $Password
Add-LocalGroupMember -Group 'Administrators' -Member $HotWork

Set-LocalUser -Name 'Administrator' -Password $Password
Rename-LocalUser -Name 'Administrator' -NewName 'DefaultHotWork'

$ListOfUsers = Get-LocalUser
foreach ($User in $ListOfUsers) {
    Write-Output $User
    if ($User.name -eq 'HotWork') {
        pass
    }
    else {
        Set-LocalUser -Name $User -Password $Password
#        Disable-LocalUser -Name $User
    }
}

# MICROSOFT SECURITY TOOLKIT COMPLIANCE HERE (PAGES 6-8a)

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord
Disable-PSRemoting
%windir%\system32\Configure-SMremoting.exe -disable
Set-Service -Name WinRM -disable
Stop-Service -Name "Spooler" -force
Set-Service -Name "Spooler" -startupType Disabled
Stop-Service -Name "RemoteRegistry" -force
Set-Service -Name "RemoteRegistry" -startupType Disabled
Stop-Service -Name "Browser" -force
Set-Service -Name "Browser" -startupType Disabled

Set-SmbServerConfiguration -EnableSMB1Protocol $False

# FIREWALL POLICY STUFF
Write-Host 'Installing firewall...'
	# Profile settings
		(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults() # Resets Windows Firewall
		Set-Variable -Name 'NetworkName' -Value (Get-NetConnectionProfile | Select-Object -ExpandProperty 'Name')
		Set-NetConnectionProfile -Name $NetworkName -NetworkCategory 'Public' # Sets network connection to the Public profile
		Remove-NetFirewallRule -Name '*' # Removes default rules
		Set-NetFirewallProfile -All -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Block' -AllowUnicastResponseToMulticast 'False' -NotifyOnListen 'True' -LogMaxSizeKilobytes '32767' -LogAllowed 'True' -LogBlocked 'True' -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
	# Enabled rules (INBOUND)
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Svchost' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Windows Defender' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Windows Defender\MSASCui.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Windows Update' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:SystemRoot\System32\wuauclt.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64) - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64) - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86) - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86) - DNS' -Protocol 'UDP' -LocalPort '53' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Microsoft Edge - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$EdgeDir\MicrosoftEdge.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Microsoft Edge - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$EdgeDir\MicrosoftEdge.exe"
    # Enabled rules (OUTBOUND)
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Palo Alto Management' -Protocol 'TCP' -RemoteAddress '172.31.37.2' -RemotePort '443'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test HTTP Service' -Protocol 'TCP' -RemoteAddress '172.25.37.11' -RemotePort '80'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test HTTPS Service' -Protocol 'TCP' -RemoteAddress '172.25.37.97' -RemotePort '443'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test DNS Service' -Protocol 'UDP' -RemoteAddress '172.25.37.23' -RemotePort '53'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test AD/DNS & NTP Services' -Protocol 'UDP' -RemoteAddress '172.25.37.27' -RemotePort '53','123','389'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test AD/DNS Service' -Protocol 'TCP' -RemoteAddress '172.25.37.27' -RemotePort '389','445'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test POP3 & SMTP' -Protocol 'TCP' -RemoteAddress '172.25.37.39' -RemotePort '25','110'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Drop All Other PA Inside Addresses' -RemoteAddress '172.25.37.0/24' -Action 'Block'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'DNS' -Protocol 'UDP' -RemotePort '53' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Malwarebytes - Service' -Protocol 'TCP' -RemotePort '80','443' -Program "\Malwarebytes\Anti-Malware\MBAMService.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Malwarebytes - Tray' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Malwarebytes\Anti-Malware\mbamtray.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Nslookup' -Protocol 'UDP' -RemotePort '53' -Program "$env:SystemRoot\System32\nslookup.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Svchost' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Windows Defender' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Windows Defender\MSASCui.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Windows Update' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:SystemRoot\System32\wuauclt.exe"
	# Disabled rules
		Set-Variable -Name 'EdgeDir' -Value (Resolve-Path -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_*" | Select-Object -ExpandProperty 'Path')
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64)' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86)' -Protocol 'TCP' -RemotePort '80','443' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Microsoft Edge' -Protocol 'TCP' -RemotePort '80','443' -Program "$EdgeDir\MicrosoftEdge.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'True' -DisplayName 'Nmap' -RemoteAddress '172.25.37.0/24' -Program "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'PowerShell' -Protocol 'TCP' -RemotePort '443' -Program "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Zenmap' -RemoteAddress '172.25.37.0/24' -Program "${env:ProgramFiles(x86)}\Nmap\zenmap.exe"
		Write-Host 'Done.'




# DOWNLOAD AND SECURE FIREFOX! Y E A H
Invoke-WebRequest -Uri 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' -OutFile "$env:UserProfile\Desktop\FirefoxInstaller.exe" # Downloads Mozilla Firefox
New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Mozilla Firefox - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Mozilla Firefox - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Mozilla Firefox - HTTP/HTTPS' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"