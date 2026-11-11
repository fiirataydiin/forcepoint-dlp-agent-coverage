#requires -Version 5.1

<#
.SYNOPSIS
    Forcepoint DLP - Ajan kapsam raporu: Active Directory kullanicilarini Forcepoint Endpoint Status
    kullanicilariyla karsilastirir, Forcepoint ajani kurulu gorunmeyen kullanicilari raporlar.

.DESCRIPTION
    YALNIZCA OKUMA YAPAR. SQL veritabaninda ve Active Directory'de hicbir kayit silinmez veya degistirilmez.
    (Eski Endpoint Status kayitlarini silmek icin ayri ForcepointAgentCleanup scripti kullanilir.)

    Akis:
      1. SQL Server'a baglanir (sqlcmd.exe, Windows veya SQL Login) ve Endpoint Status listesini okur
         (PA_DYNAMIC_STATUS + PA_DYNAMIC_STATUS_PROPS, FSM konsolu Status > Endpoint Status ile ayni).
      2. Kisa agent ozeti verir: toplam agent ve 7 / 15 / 30 gundur erismeyen agent sayilari.
      3. Active Directory'ye baglanir (mevcut oturum veya farkli domain hesabi; RSAT gerekmez) ve
         girilen OU yolundaki AKTIF kullanicilari okur.
      4. AD kullanicilarini Endpoint Status 'Logged-in Users' (eps_os_LoggedInUsers) bilgisiyle eslestirir:
           - Forcepoint ajani OLMAYAN aktif AD kullanicilari
           - Forcepoint ajani OLAN aktif AD kullanicilari
           - Ajani olan ama makinesi uzun suredir (varsayilan 30+ gun) Forcepoint'e baglanmayan kullanicilar
           - Ayni makinede birden fazla kullanici oturumu olan makineler
           - AD'de bulunamayan Forcepoint kullanicilari
      5. Sonucu masaustune CSV olarak kaydeder.

    Kullanici filtresi: (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))
                          (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
    (Yalnizca AKTIF kullanicilar; devre disi hesaplar, grup, bilgisayar ve contact nesneleri alinmaz).

    Hazirlayan: FIRAT AYDIN

.EXAMPLE
    .\ForcepointAgentCoverage.ps1

.EXAMPLE
    .\ForcepointAgentCoverage.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa

.EXAMPLE
    .\ForcepointAgentCoverage.ps1 -AdServer DC01.firma.local -AdUseCredential -AdSearchBase "OU=Kullanicilar,DC=firma,DC=local"
#>

[CmdletBinding()]
param(
    [string]$SqlServerInstance = '',

    [string]$SqlDatabaseName = 'wbsn-data-security',

    [ValidateSet('Windows', 'SqlLogin')]
    [string]$SqlAuthMode = 'Windows',

    [string]$SqlUserName = '',

    # DC adi/IP (bos = sunucunun domain'i otomatik bulunur)
    [string]$AdServer = '',

    # Kullanicilarin bulundugu OU yolu (verilmezse ekranda sorulur; bos = tum domain;
    # ';' ile birden fazla OU; DC= kismi yazilmazsa domain otomatik eklenir)
    [string]$AdSearchBase = '',

    # Baglanti menusunu atlayip dogrudan farkli domain hesabi sor
    # (parametre verilmezse ekranda 1 = mevcut oturum / 2 = farkli hesap secimi sunulur)
    [switch]$AdUseCredential,

    # Ajani olan kullanicilarda "uzun suredir gorulmuyor" esigi (gun)
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Thresholds = @(7, 15, 30)
$script:SecurePassword = $null

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

# sqlcmd ile verilen SQL'i calistirir, cikti satirlarini dondurur. Hata olursa throw eder.
function Invoke-FpSql {
    param([Parameter(Mandatory)] [string]$Sql)

    $sqlCmdExe = Get-Command 'sqlcmd.exe' -ErrorAction SilentlyContinue
    if (-not $sqlCmdExe) { throw 'sqlcmd.exe PATH icinde bulunamadi (SQL Server Command Line Utilities veya SSMS gerekli).' }

    $tempDir = Join-Path $env:ProgramData 'FpDlpHealthTemp'
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $sqlFile = Join-Path $tempDir 'fp_agent_coverage.sql'
    $outFile = Join-Path $tempDir 'fp_agent_coverage_result.txt'
    Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    Set-Content -LiteralPath $sqlFile -Value $Sql -Encoding UTF8

    $sqlArgs = [System.Collections.Generic.List[string]]::new()
    [void]$sqlArgs.AddRange([string[]]@('-S', $SqlServerInstance, '-d', $SqlDatabaseName, '-i', $sqlFile, '-o', $outFile, '-h', '-1', '-W', '-s', '|', '-f', '65001', '-b'))

    $plainPassword = $null
    $passwordPointer = [IntPtr]::Zero
    try {
        if ($SqlAuthMode -eq 'Windows') {
            [void]$sqlArgs.Add('-E')
        }
        else {
            if (-not $script:SecurePassword) {
                $script:SecurePassword = Read-Host -Prompt "SQL Server parolası ($SqlUserName)" -AsSecureString
            }
            $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:SecurePassword)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
            [void]$sqlArgs.Add('-U'); [void]$sqlArgs.Add($SqlUserName)
            [void]$sqlArgs.Add('-P'); [void]$sqlArgs.Add($plainPassword)
        }
        $null = & $sqlCmdExe.Source $sqlArgs.ToArray() 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $plainPassword = $null
        if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    }

    $lines = @()
    if (Test-Path -LiteralPath $outFile) { $lines = @(Get-Content -LiteralPath $outFile -Encoding UTF8) }
    Remove-Item -Path $sqlFile, $outFile -Force -ErrorAction SilentlyContinue

    $errLines = @($lines | Where-Object { $_ -match 'Msg \d+|Login failed|Cannot open|^ERROR\|' })
    if ($exitCode -ne 0 -or $errLines.Count -gt 0) {
        throw "sqlcmd basarisiz (cikis kodu $exitCode). $($errLines -join ' | ')"
    }
    return ,@($lines | Where-Object { $_.Trim() -ne '' })
}

# Endpoint Status kayitlarini okur (yalnizca SELECT).
function Get-FpEndpointStatus {
    $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NULL OR OBJECT_ID('PA_DYNAMIC_STATUS_PROPS','U') IS NULL
BEGIN
    SELECT 'ERROR|PA_DYNAMIC_STATUS / PA_DYNAMIC_STATUS_PROPS tablolari bulunamadi.';
    RETURN;
END
SELECT
    ISNULL(REPLACE(s.[KEY],'|','/'),'') + '|' +
    ISNULL(CONVERT(NVARCHAR(19), s.UPDATE_DATE, 120),'') + '|' +
    ISNULL(CAST(DATEDIFF(day, s.UPDATE_DATE, GETDATE()) AS NVARCHAR(10)),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_IPAddress' THEN p.STR_VALUE END),'|','/'),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_LoggedInUsers' THEN p.STR_VALUE END),'|','/'),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_AgentInstallationVersion' THEN p.STR_VALUE END),'|','/'),'')
FROM PA_DYNAMIC_STATUS s
LEFT JOIN PA_DYNAMIC_STATUS_PROPS p ON p.DYNAMIC_STATUS_ID = s.ID
GROUP BY s.ID, s.[KEY], s.UPDATE_DATE
ORDER BY s.UPDATE_DATE;
'@
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($l in (Invoke-FpSql -Sql $sql)) {
        $p = $l -split '\|'
        if ($p.Count -lt 6 -or $p[0] -eq '') { continue }
        [void]$rows.Add([pscustomobject]@{
            Hostname      = $p[0]
            LastUpdate    = $p[1]
            DaysAgo       = if ($p[2] -match '^-?\d+$') { [int]$p[2] } else { $null }
            IpAddress     = $p[3]
            LoggedInUsers = $p[4]
            Version       = $p[5]
        })
    }
    return ,$rows.ToArray()
}

# AD'deki AKTIF kullanici hesaplarini dondurur (yalnizca okuma, RSAT gerekmez).
# Bilgisayar hesaplarinin objectClass'inda da person/user oldugu icin objectCategory=person
# ve !(objectClass=computer) ile ayristirilir.
function Get-AdUserList {
    param(
        [string]$Server = '',
        [string]$SearchBase = '',
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    Add-Type -AssemblyName System.DirectoryServices

    $prefix = if ([string]::IsNullOrWhiteSpace($Server)) { 'LDAP://' } else { "LDAP://$($Server.Trim())/" }

    $newEntry = {
        param([string]$Path)
        if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            New-Object System.DirectoryServices.DirectoryEntry($Path)
        }
    }

    $rootDse = & $newEntry "${prefix}RootDSE"
    $domainDn = [string]$rootDse.Properties['defaultNamingContext'].Value
    if ([string]::IsNullOrWhiteSpace($domainDn)) {
        throw 'Domain bilgisi okunamadi (RootDSE). Sunucu domain uyesi degilse -AdServer ve -AdUseCredential kullanin.'
    }
    $base = $domainDn
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        # 'LDAP://' / 'LDAP://sunucu/' oneki atilir; DC= kismi yazilmamissa domain DN otomatik eklenir.
        $base = ($SearchBase.Trim() -replace '^LDAP://(?:[^/]+/)?', '').Trim()
        if ($base -notmatch '(^|,)\s*DC=') { $base = "$base,$domainDn" }
    }
    $dcName = [string]$rootDse.Properties['dnsHostName'].Value

    $root = & $newEntry "$prefix$base"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    # Sadece AKTIF hesaplar: userAccountControl ACCOUNTDISABLE (2) biti set olanlar LDAP tarafinda elenir.
    $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.PageSize = 1000   # 1000'den fazla kullanici icin sayfali okuma
    $attrs = @('samaccountname', 'userprincipalname', 'displayname', 'mail', 'distinguishedname', 'lastlogontimestamp')
    foreach ($a in $attrs) { [void]$searcher.PropertiesToLoad.Add($a) }

    $rows = New-Object System.Collections.Generic.List[object]
    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            $pr = $r.Properties
            $get = { param($n) if ($pr.Contains($n) -and $pr[$n].Count -gt 0) { $pr[$n][0] } else { $null } }

            $llt = & $get 'lastlogontimestamp'
            $lastLogon = $null
            if ($null -ne $llt -and [long]$llt -gt 0) {
                try { $lastLogon = [DateTime]::FromFileTime([long]$llt).ToString('yyyy-MM-dd HH:mm:ss') } catch {}
            }

            [void]$rows.Add([pscustomobject]@{
                SamAccountName    = [string](& $get 'samaccountname')
                UserPrincipalName = [string](& $get 'userprincipalname')
                DisplayName       = [string](& $get 'displayname')
                Mail              = [string](& $get 'mail')
                LastLogon         = $lastLogon
                DistinguishedName = [string](& $get 'distinguishedname')
            })
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }

    return [pscustomobject]@{
        DomainDn   = $domainDn
        SearchBase = $base
        DcName     = $dcName
        Users      = $rows.ToArray()
    }
}

# AD/LDAP hatasini anlasilir Turkce metne cevirir (ic hata zincirindeki HRESULT'a bakar).
function Get-AdErrorText {
    param([System.Exception]$Exception)
    $ex = $Exception
    while ($ex) {
        switch ($ex.HResult) {
            -2147023570 { return 'Kullanıcı adı veya parola hatalı (ya da hesap kilitli/devre dışı).' }   # 0x8007052E
            -2147016646 { return 'Sunucu erişilemiyor. DC adını ve LDAP (389) erişimini kontrol edin.' }    # 0x8007203A
            -2147016694 { return 'Domain / DC bulunamadı. Sunucu domain üyesi değilse DC veya domain adını girin.' } # 0x8007200A
            -2147024891 { return 'Erişim reddedildi. Hesabın AD okuma yetkisi yok.' }                      # 0x80070005
            -2147016656 { return 'OU yolu bulunamadı. Yolu kontrol edin (örnek: OU=Kullanicilar,DC=firma,DC=local).' } # 0x80072030
            -2147016654 { return 'OU yolu geçersiz biçimde. Örnek: OU=Kullanicilar,DC=firma,DC=local' }              # 0x80072032
        }
        if (-not $ex.InnerException) { break }
        $ex = $ex.InnerException
    }
    return $Exception.Message
}

# Farkli domain hesabi icin DC/domain, kullanici adi ve parolayi ekrandan alir.
function Read-AdCredential {
    param([string]$DefaultServer = '')
    $srvPrompt = if ($DefaultServer) { "DC veya domain adı [$DefaultServer]" } else { 'DC veya domain adı (örnek: dc01.firma.local veya firma.local, boş = otomatik)' }
    $srv = (Read-Host -Prompt $srvPrompt).Trim()
    if ($srv -eq '') { $srv = $DefaultServer }
    $user = (Read-Host -Prompt 'AD kullanıcı adı (DOMAIN\kullanici veya kullanici@firma.local)').Trim()
    if ($user -eq '') { return $null }
    $pass = Read-Host -Prompt "AD parolası ($user)" -AsSecureString
    return [pscustomobject]@{
        Server     = $srv
        Credential = New-Object System.Management.Automation.PSCredential($user, $pass)
    }
}

# Kullanicilarin bulundugu OU yolunu ekrandan alir (bos = tum domain, ';' ile birden fazla OU).
function Read-AdSearchBase {
    $dcPart = 'DC=firma,DC=local'
    if ($env:USERDNSDOMAIN) { $dcPart = (@($env:USERDNSDOMAIN.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object { "DC=$_" }) -join ',') }
    Write-Host ''
    Write-Host 'Kullanıcıların bulunduğu OU yolunu girin (boş bırakılırsa tüm domain taranır).'
    Write-Host "  Örnek          : OU=Kullanicilar,$dcPart" -ForegroundColor DarkGray
    Write-Host "  Alt OU örneği  : OU=Muhasebe,OU=Kullanicilar,$dcPart" -ForegroundColor DarkGray
    Write-Host '  Birden fazla OU: noktalı virgül (;) ile ayırın. DC= kısmı yazılmazsa domain otomatik eklenir.' -ForegroundColor DarkGray
    Write-Host '  (OU yolu: ADUC > OU > Properties > Attribute Editor > distinguishedName)' -ForegroundColor DarkGray
    return (Read-Host -Prompt 'OU yolu').Trim()
}

# AD baglanti turunu ve OU yolunu sorar, baglanir; hata veya bos sonucta farkli hesapla veya
# farkli OU ile tekrar denemeyi teklif eder. Birden fazla OU sonucu birlestirilir (DN'e gore tekil).
# Basarili olursa Get-AdUserList bicimindeki sonucu, vazgecilirse $null dondurur.
function Connect-AdInteractive {
    param(
        [string]$Server = '',
        [string]$SearchBase = '',
        [switch]$UseCredential
    )
    $askCred = [bool]$UseCredential
    if (-not $askCred) {
        Write-Host 'AD (LDAP) bağlantı türü seçin:'
        Write-Host "  1 = Mevcut Windows oturumu ile bağlan (varsayılan: $env:USERDOMAIN\$env:USERNAME)"
        Write-Host '  2 = Farklı domain hesabı ile bağlan (kullanıcı adı/parola)'
        Write-Host '  0 = Vazgeç'
        $c = (Read-Host -Prompt 'Seçiminiz [1]').Trim()
        if ($c -eq '0') { return $null }
        $askCred = ($c -eq '2')
    }

    # -AdSearchBase parametresi verilmediyse OU yolu ekrandan sorulur.
    if ([string]::IsNullOrWhiteSpace($SearchBase)) { $SearchBase = Read-AdSearchBase }

    $cred = $null
    $maxAttempts = 3
    try {
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            if ($askCred) {
                $conn = Read-AdCredential -DefaultServer $Server
                if (-not $conn) { Write-Host 'Kullanıcı adı girilmedi.' -ForegroundColor DarkYellow; return $null }
                $Server = $conn.Server
                $cred = $conn.Credential
                $askCred = $false
            }
            $who = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (mevcut oturum)" }
            $bases = @($SearchBase -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            if ($bases.Count -eq 0) { $bases = @('') }
            $currentBase = ''
            try {
                $users = New-Object System.Collections.Generic.List[object]
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                $baseTexts = New-Object System.Collections.Generic.List[string]
                $first = $null
                foreach ($b in $bases) {
                    $currentBase = if ($b) { $b } else { '(tüm domain)' }
                    $r = Get-AdUserList -Server $Server -SearchBase $b -Credential $cred
                    if (-not $first) { $first = $r }
                    [void]$baseTexts.Add($r.SearchBase)
                    $cnt = 0
                    foreach ($u in @($r.Users)) { if ($seen.Add([string]$u.DistinguishedName)) { [void]$users.Add($u); $cnt++ } }
                    if ($bases.Count -gt 1) { Write-Host ("  {0} : {1} kullanıcı" -f $r.SearchBase, $cnt) -ForegroundColor DarkGray }
                }
                if ($users.Count -gt 0) {
                    return [pscustomobject]@{
                        DomainDn   = $first.DomainDn
                        SearchBase = ($baseTexts -join ' ; ')
                        DcName     = $first.DcName
                        Users      = $users.ToArray()
                    }
                }
                Write-Host "AD bağlantısı kuruldu ancak hiç kullanıcı dönmedi ($who, OU: $SearchBase). OU yolu yanlış olabilir veya hesabın okuma yetkisi olmayabilir." -ForegroundColor Yellow
            }
            catch {
                Write-Host "AD bağlantısı / sorgu BAŞARISIZ ($who, OU: $currentBase): $(Get-AdErrorText -Exception $_.Exception)" -ForegroundColor Red
            }

            if ($attempt -ge $maxAttempts) {
                Write-Host "Deneme hakkı ($maxAttempts) doldu." -ForegroundColor DarkYellow
                return $null
            }
            Write-Host ''
            Write-Host '  1 = Farklı domain hesabı ile tekrar dene'
            Write-Host '  2 = OU yolunu değiştirip tekrar dene'
            Write-Host '  0 = Vazgeç'
            $sel = (Read-Host -Prompt 'Seçiminiz [1]').Trim()
            if ($sel -eq '0') { return $null }
            if ($sel -eq '2') { $SearchBase = Read-AdSearchBase }
            else { $askCred = $true }
        }
    }
    finally { $cred = $null }
    return $null
}

# Endpoint Status 'Logged-in Users' degerini hesap adlarina ayirir.
# 'DOMAIN\kullanici', 'kullanici@domain.local' ve virgul/noktali virgulle ayrilmis
# birden fazla kullanici bicimlerini destekler; domain kismi atilir.
function Get-FpAccountNames {
    param([string]$Value)
    $names = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Value)) { return ,$names.ToArray() }
    foreach ($part in ($Value -split '[,;]')) {
        $n = $part.Trim()
        if ($n.Contains('\')) { $n = $n.Substring($n.LastIndexOf('\') + 1) }
        if ($n.Contains('@')) { $n = $n.Substring(0, $n.IndexOf('@')) }
        $n = $n.Trim()
        if ($n -ne '' -and -not $names.Contains($n)) { [void]$names.Add($n) }
    }
    return ,$names.ToArray()
}

# AD kullanicilarini Endpoint Status kullanicilariyla karsilastirir ve raporlar.
# Eslesme: SamAccountName, UPN'in @ oncesi ve DisplayName (buyuk/kucuk harf duyarsiz).
function Invoke-AdComparison {
    param([object[]]$Endpoints, [object]$Ad)

    # Forcepoint kullanici adi -> endpoint listesi
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $fpIndex = New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp)
    $noUserEndpoints = 0
    # Ayni makinede birden fazla kullanici oturumu olan endpointler (tek ajan, birden fazla kullanici)
    $sharedEps = New-Object System.Collections.Generic.List[object]
    foreach ($ep in @($Endpoints)) {
        $names = Get-FpAccountNames -Value $ep.LoggedInUsers
        if ($names.Count -eq 0) { $noUserEndpoints++; continue }
        if ($names.Count -gt 1) { [void]$sharedEps.Add([pscustomobject]@{ Endpoint = $ep; Names = $names }) }
        foreach ($n in $names) {
            if (-not $fpIndex.ContainsKey($n)) { $fpIndex[$n] = New-Object System.Collections.Generic.List[object] }
            if (-not $fpIndex[$n].Contains($ep)) { [void]$fpIndex[$n].Add($ep) }
        }
    }

    $adKeySet = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
    $adByKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp)
    $matchedHosts = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
    $sharedEpList = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sharedEps) { [void]$sharedEpList.Add($s.Endpoint) }
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($u in @($Ad.Users)) {
        $keys = @($u.SamAccountName)
        if ($u.UserPrincipalName) { $keys += $u.UserPrincipalName.Split('@')[0] }
        if ($u.DisplayName) { $keys += $u.DisplayName }
        $hits = New-Object System.Collections.Generic.List[object]
        foreach ($k in $keys) {
            if ([string]::IsNullOrWhiteSpace($k)) { continue }
            [void]$adKeySet.Add($k.Trim())
            if (-not $adByKey.ContainsKey($k.Trim())) { $adByKey[$k.Trim()] = $u }
            if ($fpIndex.ContainsKey($k.Trim())) {
                foreach ($ep in $fpIndex[$k.Trim()]) { if (-not $hits.Contains($ep)) { [void]$hits.Add($ep) } }
            }
        }
        foreach ($h in $hits) { [void]$matchedHosts.Add([string]$h.Hostname) }
        $sharedHits = @($hits | Where-Object { $sharedEpList.Contains($_) })
        $dated = @($hits | Where-Object { $null -ne $_.DaysAgo })
        $minDays = if ($dated.Count -gt 0) { ($dated | Measure-Object -Property DaysAgo -Minimum).Minimum } else { $null }
        [void]$report.Add([pscustomobject]@{
            SamAccountName    = $u.SamAccountName
            DisplayName       = $u.DisplayName
            Mail              = $u.Mail
            FpAjani           = if ($hits.Count -gt 0) { 'Var' } else { 'Yok' }
            FpMakineler       = (@($hits | ForEach-Object { $_.Hostname } | Sort-Object -Unique) -join ', ')
            OrtakMakine       = if ($sharedHits.Count -gt 0) { 'Evet' } elseif ($hits.Count -gt 0) { 'Hayır' } else { '' }
            FpSonGorulmeGun   = $minDays
            UzunSureGorulmuyor = if ($null -ne $minDays -and $minDays -ge $StaleDays) { 'Evet' } elseif ($hits.Count -gt 0) { 'Hayır' } else { '' }
            AdLastLogon       = $u.LastLogon
            UserPrincipalName = $u.UserPrincipalName
            DistinguishedName = $u.DistinguishedName
        })
    }

    $all = $report.ToArray()
    $missing = @($all | Where-Object { $_.FpAjani -eq 'Yok' } | Sort-Object SamAccountName)
    $matched = @($all | Where-Object { $_.FpAjani -eq 'Var' } | Sort-Object SamAccountName)
    $stale = @($matched | Where-Object { $_.UzunSureGorulmuyor -eq 'Evet' } | Sort-Object FpSonGorulmeGun -Descending)

    Write-Section -Title 'AD KULLANICI ÖZETİ VE FORCEPOINT AJAN DURUMU'
    [pscustomobject]@{
        'Kapsam'                          = 'Aktif (enabled) AD kullanıcısı'
        'AD Adet'                         = $all.Count
        'FP ajanı olan'                   = $matched.Count
        'FP ajanı olmayan'                = $missing.Count
        "Ajanı var, $StaleDays+ gün görülmüyor" = $stale.Count
    } | Format-Table -AutoSize | Out-Host

    $color = if ($missing.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("Forcepoint ajanı kurulu görünmeyen AKTİF kullanıcı sayısı: {0}" -f $missing.Count) -ForegroundColor $color
    Write-Host ("FP ajanı olan {0} aktif kullanıcı toplam {1} farklı makinede oturum açmış." -f $matched.Count, $matchedHosts.Count) -ForegroundColor White
    if ($stale.Count -gt 0) {
        Write-Host ("Ajanı olan ama makinesi {0}+ gündür Forcepoint'e bağlanmayan kullanıcı sayısı: {1} (ayrıntı aşağıda)" -f $StaleDays, $stale.Count) -ForegroundColor Yellow
    }
    if ($sharedEps.Count -gt 0) {
        Write-Host ("Birden fazla kullanıcının oturum açtığı (ortak) makine sayısı: {0} (ayrıntı aşağıda)" -f $sharedEps.Count) -ForegroundColor Yellow
    }
    if ($noUserEndpoints -gt 0) {
        Write-Host ("Kullanıcı bilgisi boş endpoint sayısı: {0} (bu makinelerin kullanıcısı eşleştirilemez)" -f $noUserEndpoints) -ForegroundColor DarkYellow
    }
    Write-Host 'NOT: Eşleşme Endpoint Status ''Logged-in Users'' alanına göre yapılır. Ajan kurulu olduğu halde o an oturum açmamış kullanıcılar "Yok" görünebilir.' -ForegroundColor DarkGray

    Write-Section -Title "FORCEPOINT AJANI OLMAYAN AKTİF AD KULLANICILARI ($($missing.Count))"
    if ($missing.Count -gt 0) {
        $missing | Format-Table @{ L = 'Kullanıcı'; E = { $_.SamAccountName } },
                                @{ L = 'Ad Soyad'; E = { $_.DisplayName } },
                                @{ L = 'E-posta'; E = { $_.Mail } },
                                @{ L = 'AD Son Oturum'; E = { $_.AdLastLogon } } -AutoSize | Out-Host
    }
    else { Write-Host 'Tüm aktif AD kullanıcıları Forcepoint Endpoint Status listesinde eşleşti.' -ForegroundColor Green }

    Write-Section -Title "FORCEPOINT AJANI OLAN AKTİF AD KULLANICILARI ($($matched.Count))"
    if ($matched.Count -gt 0) {
        $matched | Format-Table @{ L = 'Kullanıcı'; E = { $_.SamAccountName } },
                                @{ L = 'Ad Soyad'; E = { $_.DisplayName } },
                                @{ L = 'FP Makine(ler)'; E = { $_.FpMakineler } },
                                @{ L = 'Ortak Makine'; E = { $_.OrtakMakine } },
                                @{ L = 'FP Son Görülme (gün)'; E = { $_.FpSonGorulmeGun }; A = 'Right' } -AutoSize | Out-Host
    }
    else { Write-Host 'Eşleşen kullanıcı yok.' -ForegroundColor DarkYellow }

    # Ajani var ama makinesi uzun suredir Forcepoint'e baglanmiyor: ajan fiilen calismiyor olabilir.
    Write-Section -Title "AJANI OLAN AMA $StaleDays+ GÜNDÜR GÖRÜLMEYEN KULLANICILAR ($($stale.Count))"
    if ($stale.Count -gt 0) {
        Write-Host 'Bu kullanıcıların makinesi uzun süredir Forcepoint''e bağlanmıyor; ajan kaldırılmış, bozuk veya makine kullanılmıyor olabilir.' -ForegroundColor DarkGray
        $stale | Format-Table @{ L = 'Kullanıcı'; E = { $_.SamAccountName } },
                              @{ L = 'Ad Soyad'; E = { $_.DisplayName } },
                              @{ L = 'FP Makine(ler)'; E = { $_.FpMakineler } },
                              @{ L = 'FP Son Görülme (gün)'; E = { $_.FpSonGorulmeGun }; A = 'Right' },
                              @{ L = 'AD Son Oturum'; E = { $_.AdLastLogon } } -AutoSize | Out-Host
    }
    else { Write-Host "Ajanı olan tüm kullanıcıların makinesi son $StaleDays gün içinde Forcepoint'e bağlanmış." -ForegroundColor Green }

    # Ayni makinede birden fazla kullanici: tek ajan birden fazla kullaniciyi kapsar.
    Write-Section -Title "AYNI MAKİNEDE BİRDEN FAZLA KULLANICI OTURUMU OLAN MAKİNELER ($($sharedEps.Count))"
    if ($sharedEps.Count -gt 0) {
        Write-Host 'Bu makinelerde tek Forcepoint ajanı birden fazla kullanıcıyı kapsıyor; bu kullanıcılar yukarıda ayrı ayrı "ajanı var" sayılır.' -ForegroundColor DarkGray
        $sharedEps | Sort-Object @{ E = { $_.Names.Count }; Descending = $true }, @{ E = { $_.Endpoint.Hostname } } | ForEach-Object {
            $labels = foreach ($n in $_.Names) {
                if ($adByKey.ContainsKey($n)) {
                    $dn = [string]$adByKey[$n].DisplayName
                    if ($dn) { "$n ($dn)" } else { $n }
                }
                else { "$n (AD'de yok)" }
            }
            [pscustomobject]@{
                Hostname                   = $_.Endpoint.Hostname
                IP                         = $_.Endpoint.IpAddress
                'Kullanıcı Sayısı'         = $_.Names.Count
                'Oturum Açan Kullanıcılar' = ($labels -join ', ')
                'Gün'                      = $_.Endpoint.DaysAgo
            }
        } | Format-Table -AutoSize | Out-Host
    }
    else { Write-Host 'Birden fazla kullanıcının oturum açtığı makine yok.' -ForegroundColor Green }

    # Forcepoint'te olup AD'de karsiligi olmayan kullanicilar (yerel hesap, farkli domain vb.)
    $fpOnly = @($fpIndex.Keys | Where-Object { -not $adKeySet.Contains($_) } | Sort-Object)
    Write-Section -Title "AD'DE BULUNAMAYAN FORCEPOINT KULLANICILARI ($($fpOnly.Count))"
    if ($fpOnly.Count -gt 0) {
        Write-Host '(Yerel hesap, AD''de devre dışı, farklı domain veya OU dışında kalan kullanıcılar olabilir.)' -ForegroundColor DarkGray
        $fpOnly | ForEach-Object {
            [pscustomobject]@{ 'FP Kullanıcı' = $_; 'Makine(ler)' = (@($fpIndex[$_] | ForEach-Object { $_.Hostname } | Sort-Object -Unique) -join ', ') }
        } | Format-Table -AutoSize | Out-Host
    }
    else { Write-Host 'Forcepoint kullanıcılarının tamamı AD''de bulundu.' -ForegroundColor Green }

    $csv = Join-Path ([Environment]::GetFolderPath('Desktop')) ("Forcepoint_Ajan_Kapsam_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $all | Sort-Object FpAjani, SamAccountName |
        Select-Object SamAccountName, DisplayName, Mail, FpAjani, FpMakineler, OrtakMakine, FpSonGorulmeGun, UzunSureGorulmuyor, AdLastLogon, UserPrincipalName, DistinguishedName |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Rapor CSV kaydedildi: $csv" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------------
# 1) SQL baglantisi
# ------------------------------------------------------------------------------------
Write-Section -Title 'FORCEPOINT DLP - AJAN KAPSAM RAPORU (yalnızca okuma)'

if ([string]::IsNullOrWhiteSpace($SqlServerInstance)) {
    $SqlServerInstance = Read-Host -Prompt 'SQL Server adı (örnek: SUNUCUADI veya SUNUCUADI\INSTANCE)'
}
if (-not $PSBoundParameters.ContainsKey('SqlAuthMode')) {
    Write-Host ''
    Write-Host 'Kimlik doğrulama türü seçin:'
    Write-Host '  1 = Windows kimlik doğrulama (varsayılan, mevcut oturumla bağlanır)'
    Write-Host '  2 = SQL Server kimlik doğrulama (kullanıcı adı/parola)'
    $authChoice = Read-Host -Prompt 'Seçiminiz [1]'
    if ($authChoice.Trim() -eq '2') { $SqlAuthMode = 'SqlLogin' }
}
if ($SqlAuthMode -eq 'SqlLogin' -and [string]::IsNullOrWhiteSpace($SqlUserName)) {
    $SqlUserName = Read-Host -Prompt 'SQL Server kullanıcı adı'
}

try {
    $endpoints = Get-FpEndpointStatus
}
catch {
    Write-Host "SQL Server bağlantısı / sorgu BAŞARISIZ: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "SQL Server bağlantısı: BAŞARILI ($SqlServerInstance / $SqlDatabaseName)" -ForegroundColor Green

# ------------------------------------------------------------------------------------
# 2) Kisa agent ozeti (bilgi amacli)
# ------------------------------------------------------------------------------------
Write-Section -Title 'AGENT ÖZETİ'
Write-Host ("Endpoint Status'taki toplam agent sayısı : {0}" -f @($endpoints).Count) -ForegroundColor White
foreach ($t in $script:Thresholds) {
    $cnt = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $t }).Count
    $c = if ($cnt -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("{0,2} gün ve üzeri erişmeyen agent          : {1}" -f $t, $cnt) -ForegroundColor $c
}
Write-Host '(Bilgi amaçlıdır. Eski kayıtları listelemek/silmek için ForcepointAgentCleanup scriptini kullanın.)' -ForegroundColor DarkGray

if (@($endpoints).Count -eq 0) {
    Write-Host ''
    Write-Host 'Endpoint Status listesinde hiç agent yok; karşılaştırma yapılamaz.' -ForegroundColor DarkYellow
    exit 0
}

# ------------------------------------------------------------------------------------
# 3) AD baglantisi + karsilastirma
# ------------------------------------------------------------------------------------
Write-Section -Title 'ACTIVE DIRECTORY BAĞLANTISI'
$ad = Connect-AdInteractive -Server $AdServer -SearchBase $AdSearchBase -UseCredential:$AdUseCredential
if (-not $ad) {
    Write-Host ''
    Write-Host 'AD bağlantısı kurulamadı veya vazgeçildi; rapor oluşturulmadı.' -ForegroundColor DarkYellow
    exit 1
}
$dcText = if ($ad.DcName) { $ad.DcName } else { '(otomatik)' }
Write-Host "AD bağlantısı: BAŞARILI (DC: $dcText)" -ForegroundColor Green
Write-Host "Arama kökü   : $($ad.SearchBase)" -ForegroundColor DarkGray

Invoke-AdComparison -Endpoints $endpoints -Ad $ad

Write-Host 'Rapor tamamlandı. SQL ve AD üzerinde hiçbir kayıt silinmedi veya değiştirilmedi.' -ForegroundColor Green
