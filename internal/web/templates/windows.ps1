function Invoke-ReDNS {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $Mode = {{psq .Mode}}
    $DnsHost = {{psq .Host}}
    $Template = {{psq .DoHURL}}
    $ScriptUrl = {{psq .ScriptURL}}
    $Server4 = {{psq .IPv4}}
    $Server6 = {{psq .IPv6}}
    $Label = {{psq .Label}}

    $Servers = @(@($Server4, $Server6) | Where-Object { $_ })
    $Vpn = 'VPN|TAP-|TUN|WireGuard|Wintun|OpenVPN|Tailscale|ZeroTier|Hamachi|Radmin|Amnezia|Outline|Hiddify|sing-box|Clash|v2ray|Xray|WARP|Proton|Nord|Fortinet|AnyConnect|GlobalProtect'
    $Skip = "$Vpn|Bluetooth|Loopback|VirtualBox|VMware|Hyper-V"
    $Params = 'SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    $BackupKey = 'SOFTWARE\ReDNS\Backup'
    $HKLM = [Microsoft.Win32.Registry]::LocalMachine

    function Say([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }

    function Finish {
        if ($env:REDNS_PAUSE -eq '1') {
            Write-Host ''
            Read-Host 'Нажми Enter, чтобы закрыть окно' | Out-Null
        }
    }

    function Get-StaticServers([string]$Guid) {
        $out = @()
        foreach ($stack in 'Tcpip', 'Tcpip6') {
            $k = $HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\$stack\Parameters\Interfaces\$Guid")
            if ($k) {
                $v = [string]$k.GetValue('NameServer', '')
                $k.Close()
                $out += @($v -split '[,\s]+' | Where-Object { $_ -and ($Servers -notcontains $_) })
            }
        }
        $out
    }

    function Set-DohFlag([string]$Guid, [string]$Ip, [bool]$On) {
        $sub = if ($Ip.Contains(':')) { 'Doh6' } else { 'Doh' }
        $path = "$Params\$Guid\DohInterfaceSettings\$sub\$Ip"
        if ($On) {
            $k = $HKLM.CreateSubKey($path)
            $k.SetValue('DohFlags', [long]1, [Microsoft.Win32.RegistryValueKind]::QWord)
            $k.Close()
        } else {
            $HKLM.DeleteSubKeyTree($path, $false)
        }
    }

    function Get-VpnNames {
        @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'Up' -and ($_.Name + ' ' + $_.InterfaceDescription) -match $Vpn
        } | ForEach-Object { $_.Name })
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    Write-Host ''
    Say "ReDNS для Windows · $DnsHost" Cyan
    if ($Label) { Say "Устройство: $Label" DarkGray }
    Write-Host ''

    if ([Environment]::OSVersion.Version.Build -lt 22000 -or -not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        Say 'Эта версия Windows не умеет шифрованный DNS для всей системы, нужна Windows 11.' Yellow
        Say 'Настрой DoH в браузере: вкладка «Браузер» на странице настройки.' Yellow
        Finish
        return
    }

    $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Say 'Нужны права администратора. Подтверди запрос Windows, настройка продолжится в новом окне.' Cyan
        $cmd = "`$env:REDNS_PAUSE='1'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm '$ScriptUrl' | iex"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        try {
            Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc
        } catch {
            Say 'Без прав администратора системный DNS не поменять.' Red
            Finish
        }
        return
    }

    if ($Mode -eq 'remove') {
        $n = 0
        foreach ($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
            $guid = [string]$a.InterfaceGuid
            if (-not $guid) { continue }
            $current = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
            $ours = @($current | Where-Object { $Servers -contains $_ }).Count -gt 0
            foreach ($ip in $Servers) { Set-DohFlag $guid $ip $false }
            if (-not $ours) { continue }
            $saved = $HKLM.OpenSubKey("$BackupKey\$guid")
            $restore = @()
            if ($saved) {
                $restore = @(([string]$saved.GetValue('Servers', '')) -split '[,\s]+' | Where-Object { $_ })
                $saved.Close()
            }
            if ($restore.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $restore
                Say "  $($a.Name): вернул прежние DNS ($($restore -join ', '))" Gray
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
                Say "  $($a.Name): DNS снова автоматически (DHCP)" Gray
            }
            $n++
        }
        foreach ($ip in $Servers) { Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue }
        $HKLM.DeleteSubKeyTree('SOFTWARE\ReDNS', $false)
        Clear-DnsClientCache
        Write-Host ''
        if ($n -gt 0) { Say 'Готово: ReDNS убран из настроек Windows.' Green } else { Say 'ReDNS в настройках Windows не найден, менять нечего.' Green }
        Finish
        return
    }

    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.ifIndex })
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -ne 'Not Present' -and ($_.HardwareInterface -or $routes -contains $_.ifIndex) -and ($_.Name + ' ' + $_.InterfaceDescription) -notmatch $Skip
    })
    if ($adapters.Count -eq 0) {
        Say 'Не нашёл сетевых адаптеров Ethernet или Wi‑Fi.' Red
        Finish
        return
    }

    Say '1. Регистрирую ReDNS как DoH-сервер без отката на обычный DNS' White
    foreach ($ip in $Servers) {
        Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
        Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
    }

    Say '2. Прописываю DNS на сетевых адаптерах' White
    $done = 0
    foreach ($a in $adapters) {
        $guid = [string]$a.InterfaceGuid
        if (-not $guid) { continue }
        $keyPath = "$BackupKey\$guid"
        $old = $HKLM.OpenSubKey($keyPath)
        if ($old) {
            $old.Close()
        } else {
            $k = $HKLM.CreateSubKey($keyPath)
            $k.SetValue('Servers', ((Get-StaticServers $guid) -join ','))
            $k.SetValue('Name', [string]$a.Name)
            $k.Close()
        }
        foreach ($ip in $Servers) { Set-DohFlag $guid $ip $true }
        $set = $true
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $Servers
        } catch {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @($Server4)
            } catch {
                $set = $false
            }
        }
        if ($set) {
            Say "   $($a.Name) ($($a.InterfaceDescription))" Gray
            $done++
        } else {
            Say "   $($a.Name): пропускаю, адаптер выключен" DarkGray
        }
    }

    if ($done -eq 0) {
        Say 'Ни на одном адаптере DNS не поменялся. Включи сетевой адаптер и запусти команду ещё раз.' Red
        Finish
        return
    }

    Clear-DnsClientCache
    Start-Sleep -Seconds 2

    Say '3. Проверяю, что запросы доходят до ReDNS по DoH' White
    $nonce = -join (1..16 | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    try { Resolve-DnsName -Name "p-$nonce.$DnsHost" -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null } catch {}
    $probe = $null
    for ($i = 0; $i -lt 8; $i++) {
        try { $probe = Invoke-RestMethod -Uri "https://$DnsHost/api/probe?n=$nonce" -UseBasicParsing } catch {}
        if ($probe -and $probe.seen) { break }
        Start-Sleep -Milliseconds 500
    }

    Write-Host ''
    $active = Get-VpnNames
    if ($probe -and $probe.seen -and $probe.proto -eq 'doh') {
        Say 'Готово. Windows ходит в ReDNS по DoH с ключом.' Green
        Say 'Смена IP у провайдера больше не ломает DNS, запросы зашифрованы.' Green
    } elseif ($probe -and $probe.seen) {
        Say "DNS доходит до ReDNS, но по $($probe.proto.ToUpper()), а не по DoH." Yellow
        Say 'Перезагрузи компьютер и обнови страницу настройки: сверху должно быть «Работает» и протокол DoH.' Yellow
    } elseif ($active.Count -gt 0) {
        Say "Настройки записаны, но сейчас включён VPN ($($active -join ', ')), и DNS идёт через него." Yellow
        Say 'Выключи VPN, и Windows пойдёт в ReDNS.' Yellow
    } else {
        Say 'Настройки записаны, но проверочный запрос не дошёл до ReDNS.' Yellow
        Say 'Перезагрузи компьютер и обнови страницу настройки. Если не поможет, пришли скриншот этого окна.' Yellow
    }
    Write-Host ''
    Say 'Удалить настройку: на странице ReDNS, вкладка Windows, блок «Отменить настройку».' DarkGray
    Finish
}

try {
    Invoke-ReDNS
} catch {
    Write-Host ''
    Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Пришли скриншот этого окна.' -ForegroundColor Red
    if ($env:REDNS_PAUSE -eq '1') { Read-Host 'Нажми Enter, чтобы закрыть окно' | Out-Null }
}
