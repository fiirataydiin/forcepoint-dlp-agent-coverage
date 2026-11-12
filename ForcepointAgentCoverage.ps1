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
      6. Ayrica tek dosyalik, internet baglantisi gerektirmeyen bir HTML rapor olusturur ve tarayicida acar:
         kapsam orani grafigi, ozet kartlari, aranabilir/siralanabilir tablolar, acik/koyu tema.

    Bu script ForcepointAgentCoverage.ps1 ile ayni islemi yapar, ek olarak HTML rapor uretir.

    Kullanici filtresi: (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))
                          (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
    (Yalnizca AKTIF kullanicilar; devre disi hesaplar, grup, bilgisayar ve contact nesneleri alinmaz).

    Hazirlayan: FIRAT AYDIN

.EXAMPLE
    .\ForcepointAgentCoverageHtml.ps1

.EXAMPLE
    .\ForcepointAgentCoverageHtml.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa

.EXAMPLE
    .\ForcepointAgentCoverageHtml.ps1 -AdServer DC01.firma.local -AdUseCredential -AdSearchBase "OU=Kullanicilar,DC=firma,DC=local"

.EXAMPLE
    .\ForcepointAgentCoverageHtml.ps1 -OutputFolder "D:\Raporlar" -NoOpen
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
    [int]$StaleDays = 30,

    # CSV ve HTML raporun kaydedilecegi klasor (bos = masaustu)
    [string]$OutputFolder = '',

    # HTML raporu olusturduktan sonra tarayicida acma
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Thresholds = @(7, 15, 30)
$script:SecurePassword = $null
$script:ReportStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:OutDir = if ([string]::IsNullOrWhiteSpace($OutputFolder)) { [Environment]::GetFolderPath('Desktop') } else { $OutputFolder.Trim() }

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
    }
    # Ortak makine satirlari (konsol tablosu ve HTML rapor icin)
    $sharedRows = @($sharedEps | Sort-Object @{ E = { $_.Names.Count }; Descending = $true }, @{ E = { $_.Endpoint.Hostname } } | ForEach-Object {
        $labelObjs = @(foreach ($n in $_.Names) {
            $inAd = $adByKey.ContainsKey($n)
            $dn = if ($inAd) { [string]$adByKey[$n].DisplayName } else { '' }
            [pscustomobject]@{ Name = $n; DisplayName = $dn; InAd = $inAd }
        })
        $labels = foreach ($l in $labelObjs) { if (-not $l.InAd) { "$($l.Name) (AD'de yok)" } elseif ($l.DisplayName) { "$($l.Name) ($($l.DisplayName))" } else { $l.Name } }
        [pscustomobject]@{
            Hostname                   = $_.Endpoint.Hostname
            IP                         = $_.Endpoint.IpAddress
            'Kullanıcı Sayısı'         = $_.Names.Count
            'Oturum Açan Kullanıcılar' = ($labels -join ', ')
            'Gün'                      = $_.Endpoint.DaysAgo
            Labels                     = $labelObjs
        }
    })
    if ($sharedRows.Count -gt 0) {
        $sharedRows | Format-Table Hostname, IP, 'Kullanıcı Sayısı', 'Oturum Açan Kullanıcılar', 'Gün' -AutoSize | Out-Host
    }
    else { Write-Host 'Birden fazla kullanıcının oturum açtığı makine yok.' -ForegroundColor Green }

    # Forcepoint'te olup AD'de karsiligi olmayan kullanicilar (yerel hesap, farkli domain vb.)
    $fpOnly = @($fpIndex.Keys | Where-Object { -not $adKeySet.Contains($_) } | Sort-Object)
    $fpOnlyRows = @($fpOnly | ForEach-Object {
        [pscustomobject]@{ 'FP Kullanıcı' = $_; 'Makine(ler)' = (@($fpIndex[$_] | ForEach-Object { $_.Hostname } | Sort-Object -Unique) -join ', ') }
    })
    Write-Section -Title "AD'DE BULUNAMAYAN FORCEPOINT KULLANICILARI ($($fpOnly.Count))"
    if ($fpOnly.Count -gt 0) {
        Write-Host '(Yerel hesap, AD''de devre dışı, farklı domain veya OU dışında kalan kullanıcılar olabilir.)' -ForegroundColor DarkGray
        $fpOnlyRows | Format-Table -AutoSize | Out-Host
    }
    else { Write-Host 'Forcepoint kullanıcılarının tamamı AD''de bulundu.' -ForegroundColor Green }

    $csv = Join-Path $script:OutDir ("Forcepoint_Ajan_Kapsam_{0}.csv" -f $script:ReportStamp)
    $all | Sort-Object FpAjani, SamAccountName |
        Select-Object SamAccountName, DisplayName, Mail, FpAjani, FpMakineler, OrtakMakine, FpSonGorulmeGun, UzunSureGorulmuyor, AdLastLogon, UserPrincipalName, DistinguishedName |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Rapor CSV kaydedildi: $csv" -ForegroundColor Cyan

    # HTML rapor icin sonuc verisi
    return [pscustomobject]@{
        All              = $all
        Missing          = $missing
        Matched          = $matched
        Stale            = $stale
        Shared           = $sharedRows
        FpOnly           = $fpOnlyRows
        NoUserEndpoints  = $noUserEndpoints
        MatchedHostCount = $matchedHosts.Count
    }
}

# Tek dosyalik HTML rapor olusturur (CSS/JS gomulu, dis kaynak yok). Tum veriler HTML-encode edilir.
function New-CoverageHtml {
    param([object]$Result, [hashtable]$EndpointSummary, [object]$Ad, [string]$Path)

    function Enc($v) { if ($null -eq $v) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$v) } }
    function New-DayCell($d) {
        if ($null -eq $d -or [string]$d -eq '') { return '<td class="num" data-v="-1"><span class="muted">-</span></td>' }
        $n = [int]$d
        $cls = if ($n -ge $StaleDays) { 'bad' } elseif ($n -ge 7) { 'warn' } else { 'ok' }
        return "<td class=""num"" data-v=""$n""><span class=""pill $cls"">$n</span></td>"
    }
    function New-HtmlTable([string]$Id, [string[]]$Headers, [object[]]$Rows, [string]$Empty) {
        $Rows = @($Rows | Where-Object { $_ })
        if ($Rows.Count -eq 0) { return "<p class=""empty"">$Empty</p>" }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<div class=""tools""><input type=""search"" class=""filter"" data-target=""$Id"" data-unit=""kayıt"" placeholder=""Tabloda ara..."" aria-label=""Tabloda ara""><span class=""count"" id=""$Id-count"">$($Rows.Count) kayıt</span></div>")
        [void]$sb.Append("<div class=""tablewrap""><table id=""$Id"" class=""sortable""><thead><tr>")
        foreach ($h in $Headers) { [void]$sb.Append("<th>$h</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($r in $Rows) { [void]$sb.Append([string]$r) }
        [void]$sb.Append('</tbody></table></div>')
        return $sb.ToString()
    }

    $tr = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $total = @($Result.All).Count
    $mCount = @($Result.Matched).Count
    $xCount = @($Result.Missing).Count
    $sCount = @($Result.Stale).Count
    $shCount = @($Result.Shared).Count
    $foCount = @($Result.FpOnly).Count
    $pct = if ($total -gt 0) { [math]::Round($mCount * 100.0 / $total, 1) } else { 0 }
    $pctCss = $pct.ToString($inv)
    $pctText = '%' + $pct.ToString('0.#', $tr)

    $rowsMissing = foreach ($u in @($Result.Missing)) {
        "<tr><td class=""mono"">$(Enc $u.SamAccountName)</td><td>$(Enc $u.DisplayName)</td><td>$(Enc $u.Mail)</td><td class=""mono"">$(Enc $u.AdLastLogon)</td></tr>"
    }
    $rowsMatched = foreach ($u in @($Result.Matched)) {
        $sh = if ($u.OrtakMakine -eq 'Evet') { '<span class="tag info">Evet</span>' } else { '<span class="muted">Hayır</span>' }
        "<tr><td class=""mono"">$(Enc $u.SamAccountName)</td><td>$(Enc $u.DisplayName)</td><td class=""mono"">$(Enc $u.FpMakineler)</td><td>$sh</td>$(New-DayCell $u.FpSonGorulmeGun)</tr>"
    }
    $rowsStale = foreach ($u in @($Result.Stale)) {
        "<tr><td class=""mono"">$(Enc $u.SamAccountName)</td><td>$(Enc $u.DisplayName)</td><td class=""mono"">$(Enc $u.FpMakineler)</td>$(New-DayCell $u.FpSonGorulmeGun)<td class=""mono"">$(Enc $u.AdLastLogon)</td></tr>"
    }
    $rowsShared = foreach ($s in @($Result.Shared)) {
        $chips = foreach ($l in @($s.Labels)) {
            if (-not $l.InAd) { "<span class=""chip warn"">$(Enc $l.Name)<small>AD'de yok</small></span>" }
            elseif ($l.DisplayName) { "<span class=""chip"">$(Enc $l.Name)<small>$(Enc $l.DisplayName)</small></span>" }
            else { "<span class=""chip"">$(Enc $l.Name)</span>" }
        }
        "<tr><td class=""mono"">$(Enc $s.Hostname)</td><td class=""mono"">$(Enc $s.IP)</td><td class=""num"" data-v=""$($s.'Kullanıcı Sayısı')"">$($s.'Kullanıcı Sayısı')</td><td class=""wrap"">$($chips -join '')</td>$(New-DayCell $s.'Gün')</tr>"
    }
    $rowsFpOnly = foreach ($f in @($Result.FpOnly)) {
        "<tr><td class=""mono"">$(Enc $f.'FP Kullanıcı')</td><td class=""mono"">$(Enc $f.'Makine(ler)')</td></tr>"
    }

    $css = @'
:root{--bg:#f4f6f9;--surface:#fff;--surface2:#f0f2f6;--text:#1c2230;--muted:#667085;--border:#e2e6ec;--ok:#15803d;--ok-bg:#e3f5ea;--warn:#a16207;--warn-bg:#fef3c7;--bad:#b91c1c;--bad-bg:#fde8e8;--info:#1d4ed8;--info-bg:#e6edff;--head:#0f2747;--head-text:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1117;--surface:#161a22;--surface2:#1d222c;--text:#e6e9ef;--muted:#9aa3b2;--border:#2a303b;--ok:#4ade80;--ok-bg:#11301e;--warn:#fbbf24;--warn-bg:#3a2b08;--bad:#f87171;--bad-bg:#3b1515;--info:#93b4ff;--info-bg:#18264a;--head:#111c30;--head-text:#e6e9ef}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
.hero{background:var(--head);color:var(--head-text);padding:26px 0 70px}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px}
.hero h1{margin:0 0 4px;font-size:24px;font-weight:650}
.hero p{margin:0;opacity:.8}
.hero .top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:14px}
.ro{font-size:12px;padding:4px 12px;border-radius:999px;background:rgba(255,255,255,.14);font-weight:600;white-space:nowrap}
.main{margin-top:-50px;padding-bottom:40px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px 22px;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px 18px;margin-bottom:16px;box-shadow:0 4px 14px rgba(15,39,71,.08)}
.meta span{display:block;font-size:12px;color:var(--muted)}
.meta b{font-weight:600;word-break:break-word}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px}
.card .label{font-size:12.5px;color:var(--muted);margin-bottom:6px}
.card .value{font-size:30px;font-weight:700;line-height:1.1}
.card .hint{font-size:12.5px;color:var(--muted);margin-top:6px}
.card.bad{border-top:4px solid var(--bad)}.card.bad .value{color:var(--bad)}
.card.warn{border-top:4px solid var(--warn)}.card.warn .value{color:var(--warn)}
.card.ok{border-top:4px solid var(--ok)}.card.ok .value{color:var(--ok)}
.card.big{grid-column:span 2;display:flex;align-items:center;gap:22px}
.donut{width:122px;height:122px;border-radius:50%;display:grid;place-items:center;flex:none}
.donut::after{content:"";grid-area:1/1;width:88px;height:88px;border-radius:50%;background:var(--surface)}
.donut b{grid-area:1/1;position:relative;z-index:1;font-size:21px}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12.5px;color:var(--muted);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.strip{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px 14px;font-size:13px;color:var(--muted)}
.stat b{color:var(--text);font-size:15px;margin-left:6px}
.note{background:var(--info-bg);border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:16px}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;margin-bottom:6px}
nav.toc a{text-decoration:none;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:5px 12px;font-size:13px}
nav.toc a:hover{border-color:var(--info)}
nav.toc a b{margin-left:6px;color:var(--muted)}
section{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:16px;scroll-margin-top:60px}
section h2{font-size:17px;margin:0 0 4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
section .desc{color:var(--muted);margin:0 0 12px;font-size:13px}
.cnt{font-size:12px;padding:1px 9px;border-radius:999px;background:var(--surface2);color:var(--muted);font-weight:600}
.cnt.bad{background:var(--bad-bg);color:var(--bad)}.cnt.warn{background:var(--warn-bg);color:var(--warn)}.cnt.ok{background:var(--ok-bg);color:var(--ok)}
.tools{display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
input.filter{flex:1;min-width:180px;max-width:340px;padding:7px 11px;border:1px solid var(--border);border-radius:8px;background:var(--surface2);color:var(--text);font:inherit}
.count{color:var(--muted);font-size:12.5px}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;vertical-align:middle}
td.wrap{white-space:normal;min-width:260px}
th{background:var(--surface2);font-weight:600;cursor:pointer;user-select:none}
th::after{content:" \2195";color:var(--muted);font-size:11px}
th.asc::after{content:" \2191"}th.desc::after{content:" \2193"}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--surface2)}
.num{text-align:right}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}
.muted{color:var(--muted)}
.pill{display:inline-block;min-width:36px;text-align:center;padding:1px 8px;border-radius:999px;font-weight:600;font-size:12px}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.tag{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:600}
.tag.info{background:var(--info-bg);color:var(--info)}
.chip{display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;border-radius:6px;background:var(--surface2);border:1px solid var(--border);font-size:12.5px}
.chip small{color:var(--muted);margin-left:5px}
.chip.warn{background:var(--warn-bg);border-color:transparent;color:var(--warn)}
.chip.warn small{color:var(--warn)}
.empty{color:var(--ok);margin:4px 0;font-weight:600}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:20px}
@media (max-width:600px){.card.big{grid-column:auto;flex-direction:column;align-items:flex-start}.hero h1{font-size:20px}}
@media print{nav.toc,.tools{display:none}body{background:#fff}.hero{padding-bottom:20px}.main{margin-top:10px}section,.card,.meta{break-inside:avoid;box-shadow:none}}
'@

    $js = @'
(function(){
  var lang=document.documentElement.lang||'tr';
  document.querySelectorAll('input.filter').forEach(function(inp){
    inp.addEventListener('input',function(){
      var t=document.getElementById(inp.getAttribute('data-target'));if(!t)return;
      var q=inp.value.toLocaleLowerCase(lang).trim(),rows=t.tBodies[0].rows,n=0;
      for(var i=0;i<rows.length;i++){var ok=rows[i].textContent.toLocaleLowerCase(lang).indexOf(q)>-1;rows[i].style.display=ok?'':'none';if(ok)n++;}
      var c=document.getElementById(t.id+'-count');if(c)c.textContent=(q?n+' / ':'')+rows.length+' '+inp.getAttribute('data-unit');
    });
  });
  document.querySelectorAll('table.sortable').forEach(function(t){
    var ths=t.tHead.rows[0].cells;
    for(var k=0;k<ths.length;k++){(function(th,idx){
      th.addEventListener('click',function(){
        var asc=!th.classList.contains('asc');
        for(var j=0;j<ths.length;j++){ths[j].classList.remove('asc','desc');}
        th.classList.add(asc?'asc':'desc');
        var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows);
        var val=function(r){var c=r.cells[idx];if(!c)return '';var v=c.getAttribute('data-v');return v!==null?v:c.textContent.trim();};
        rows.sort(function(a,b){var x=val(a),y=val(b),nx=parseFloat(x),ny=parseFloat(y);
          var r=(/^-?\d+(\.\d+)?$/.test(x)&&/^-?\d+(\.\d+)?$/.test(y))?nx-ny:x.localeCompare(y,lang,{numeric:true,sensitivity:'base'});
          return asc?r:-r;});
        rows.forEach(function(r){body.appendChild(r);});
      });
    })(ths[k],k);}
  });
})();
'@

    $genAt = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $dc = if ($Ad.DcName) { $Ad.DcName } else { '(otomatik)' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.Append('<title>Forcepoint DLP Ajan Kapsam Raporu</title><style>' + $css + '</style></head><body>')
    [void]$sb.Append('<div class="hero"><div class="wrap"><div class="top"><div><h1>Forcepoint DLP &middot; Ajan Kapsam Raporu</h1>')
    [void]$sb.Append('<p>Active Directory aktif kullanıcıları ile Forcepoint Endpoint Status karşılaştırması</p></div>')
    [void]$sb.Append('<span class="ro">Yalnızca okuma &middot; hiçbir kayıt değiştirilmedi</span></div></div></div>')
    [void]$sb.Append('<div class="wrap main">')

    # Rapor bilgileri
    [void]$sb.Append('<div class="meta">')
    foreach ($m in @(
            @('Oluşturulma', $genAt), @('SQL Server / Veritabanı', "$SqlServerInstance / $SqlDatabaseName"),
            @('Domain Controller', $dc), @('Arama kökü (OU)', $Ad.SearchBase),
            @('"Uzun süredir görülmüyor" eşiği', "$StaleDays gün"), @('Çalıştıran', "$env:USERDOMAIN\$env:USERNAME @ $env:COMPUTERNAME"))) {
        [void]$sb.Append("<div><span>$(Enc $m[0])</span><b>$(Enc $m[1])</b></div>")
    }
    [void]$sb.Append('</div>')

    # Ozet kartlari
    $donutBg = "background:conic-gradient(var(--ok) 0 $pctCss%, var(--bad) $pctCss% 100%)"
    if ($total -eq 0) { $donutBg = 'background:var(--surface2)' }
    [void]$sb.Append('<div class="kpis">')
    [void]$sb.Append("<div class=""card big""><div class=""donut"" style=""$donutBg""><b>$pctText</b></div><div><div class=""label"">Ajan kapsamı</div><div class=""value"">$mCount / $total</div><div class=""hint"">aktif AD kullanıcısında Forcepoint ajanı görünüyor</div><div class=""legend""><span><i style=""background:var(--ok)""></i>Ajanı olan</span><span><i style=""background:var(--bad)""></i>Ajanı olmayan</span></div></div></div>")
    [void]$sb.Append("<div class=""card bad""><div class=""label"">Ajanı olmayan</div><div class=""value"">$xCount</div><div class=""hint"">aktif AD kullanıcısı</div></div>")
    [void]$sb.Append("<div class=""card ok""><div class=""label"">Ajanı olan</div><div class=""value"">$mCount</div><div class=""hint"">$($Result.MatchedHostCount) farklı makinede</div></div>")
    [void]$sb.Append("<div class=""card warn""><div class=""label"">Ajanı var, $StaleDays+ gün görülmüyor</div><div class=""value"">$sCount</div><div class=""hint"">ajan fiilen çalışmıyor olabilir</div></div>")
    [void]$sb.Append("<div class=""card""><div class=""label"">Ortak makine</div><div class=""value"">$shCount</div><div class=""hint"">birden fazla kullanıcı oturumu</div></div>")
    [void]$sb.Append("<div class=""card""><div class=""label"">AD'de bulunamayan</div><div class=""value"">$foCount</div><div class=""hint"">Forcepoint kullanıcısı</div></div>")
    [void]$sb.Append('</div>')

    # Endpoint Status ozeti
    [void]$sb.Append('<div class="strip">')
    [void]$sb.Append("<div class=""stat"">Endpoint Status toplam agent<b>$($EndpointSummary['Total'])</b></div>")
    foreach ($t in $script:Thresholds) { [void]$sb.Append("<div class=""stat"">$t+ gün erişmeyen agent<b>$($EndpointSummary["Stale$t"])</b></div>") }
    [void]$sb.Append("<div class=""stat"">Kullanıcı bilgisi boş endpoint<b>$($Result.NoUserEndpoints)</b></div>")
    [void]$sb.Append('</div>')
    [void]$sb.Append('<div class="note"><b>Not:</b> Eşleşme Endpoint Status &quot;Logged-in Users&quot; alanına göre yapılır. Ajan kurulu olduğu halde o an oturum açmamış kullanıcılar &quot;ajanı olmayan&quot; görünebilir.</div>')

    # Bolum menusu
    [void]$sb.Append('<nav class="toc">')
    foreach ($n in @(@('s-missing', 'Ajanı olmayan', $xCount), @('s-matched', 'Ajanı olan', $mCount), @('s-stale', "$StaleDays+ gün görülmeyen", $sCount), @('s-shared', 'Ortak makineler', $shCount), @('s-fponly', "AD'de bulunamayan", $foCount))) {
        [void]$sb.Append("<a href=""#$($n[0])"">$(Enc $n[1])<b>$($n[2])</b></a>")
    }
    [void]$sb.Append('</nav>')

    # Bolumler
    $sections = @(
        @{ Id = 's-missing'; Title = 'Forcepoint ajanı olmayan aktif AD kullanıcıları'; Count = $xCount; Cls = $(if ($xCount -gt 0) { 'bad' } else { 'ok' })
           Desc = 'Bu kullanıcılar AD''de aktif, ancak Forcepoint Endpoint Status listesinde hiçbir makinede görünmüyor.'
           Html = (New-HtmlTable 't-missing' @('Kullanıcı', 'Ad Soyad', 'E-posta', 'AD son oturum') $rowsMissing 'Tüm aktif AD kullanıcıları Forcepoint Endpoint Status listesinde eşleşti.') },
        @{ Id = 's-matched'; Title = 'Forcepoint ajanı olan aktif AD kullanıcıları'; Count = $mCount; Cls = 'ok'
           Desc = 'FP son görülme: kullanıcının makine(ler)inin Forcepoint''e en son bağlandığı günden bu yana geçen gün.'
           Html = (New-HtmlTable 't-matched' @('Kullanıcı', 'Ad Soyad', 'FP makine(ler)', 'Ortak makine', 'FP son görülme (gün)') $rowsMatched 'Eşleşen kullanıcı yok.') },
        @{ Id = 's-stale'; Title = "Ajanı olan ama $StaleDays+ gündür görülmeyen kullanıcılar"; Count = $sCount; Cls = $(if ($sCount -gt 0) { 'warn' } else { 'ok' })
           Desc = 'Bu kullanıcıların makinesi uzun süredir Forcepoint''e bağlanmıyor; ajan kaldırılmış, bozuk veya makine kullanılmıyor olabilir.'
           Html = (New-HtmlTable 't-stale' @('Kullanıcı', 'Ad Soyad', 'FP makine(ler)', 'FP son görülme (gün)', 'AD son oturum') $rowsStale "Ajanı olan tüm kullanıcıların makinesi son $StaleDays gün içinde Forcepoint'e bağlanmış.") },
        @{ Id = 's-shared'; Title = 'Aynı makinede birden fazla kullanıcı oturumu olan makineler'; Count = $shCount; Cls = ''
           Desc = 'Bu makinelerde tek Forcepoint ajanı birden fazla kullanıcıyı kapsıyor; bu kullanıcılar ayrı ayrı "ajanı var" sayılır.'
           Html = (New-HtmlTable 't-shared' @('Hostname', 'IP', 'Kullanıcı sayısı', 'Oturum açan kullanıcılar', 'Gün') $rowsShared 'Birden fazla kullanıcının oturum açtığı makine yok.') },
        @{ Id = 's-fponly'; Title = 'AD''de bulunamayan Forcepoint kullanıcıları'; Count = $foCount; Cls = ''
           Desc = 'Yerel hesap, AD''de devre dışı hesap, farklı domain veya girilen OU''nun dışında kalan kullanıcılar olabilir.'
           Html = (New-HtmlTable 't-fponly' @('FP kullanıcı', 'Makine(ler)') $rowsFpOnly 'Forcepoint kullanıcılarının tamamı AD''de bulundu.') }
    )
    foreach ($s in $sections) {
        [void]$sb.Append("<section id=""$($s.Id)""><h2>$(Enc $s.Title)<span class=""cnt $($s.Cls)"">$($s.Count)</span></h2><p class=""desc"">$(Enc $s.Desc)</p>$($s.Html)</section>")
    }

    [void]$sb.Append('<footer>ForcepointAgentCoverageHtml.ps1 ile oluşturuldu &middot; Hazırlayan: FIRAT AYDIN</footer>')
    [void]$sb.Append('</div><script>' + $js + '</script></body></html>')

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------------------------------------
# 1) SQL baglantisi
# ------------------------------------------------------------------------------------
Write-Section -Title 'FORCEPOINT DLP - AJAN KAPSAM RAPORU + HTML (yalnızca okuma)'

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
$epSummary = @{ Total = @($endpoints).Count }
foreach ($t in $script:Thresholds) {
    $cnt = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $t }).Count
    $epSummary["Stale$t"] = $cnt
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

$result = Invoke-AdComparison -Endpoints $endpoints -Ad $ad

# ------------------------------------------------------------------------------------
# 4) HTML rapor
# ------------------------------------------------------------------------------------
$htmlPath = Join-Path $script:OutDir ("Forcepoint_Ajan_Kapsam_{0}.html" -f $script:ReportStamp)
try {
    New-CoverageHtml -Result $result -EndpointSummary $epSummary -Ad $ad -Path $htmlPath
    Write-Host "HTML rapor kaydedildi: $htmlPath" -ForegroundColor Cyan
    if (-not $NoOpen) {
        try { Start-Process -FilePath $htmlPath } catch { Write-Host 'HTML rapor otomatik açılamadı; dosyayı tarayıcıda elle açın.' -ForegroundColor DarkYellow }
    }
}
catch {
    Write-Host "HTML rapor oluşturulamadı: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host 'Rapor tamamlandı. SQL ve AD üzerinde hiçbir kayıt silinmedi veya değiştirilmedi.' -ForegroundColor Green
