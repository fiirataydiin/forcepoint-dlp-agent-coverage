#requires -Version 5.1

<#
.SYNOPSIS
    Forcepoint DLP - Agent coverage report: compares Active Directory users with Forcepoint Endpoint
    Status users and reports the users that do not appear to have a Forcepoint agent.

.DESCRIPTION
    READ-ONLY. Nothing is deleted or changed in the SQL database or in Active Directory.
    (Use the separate ForcepointAgentCleanup script to delete stale Endpoint Status records.)

    Flow:
      1. Connects to SQL Server (sqlcmd.exe, Windows or SQL Login) and reads the Endpoint Status list
         (PA_DYNAMIC_STATUS + PA_DYNAMIC_STATUS_PROPS, same as the FSM console Status > Endpoint Status).
      2. Shows a short agent summary: total agents and agents not reporting for 7 / 15 / 30 days.
      3. Connects to Active Directory (current session or a different domain account; no RSAT needed)
         and reads the ENABLED users in the given OU path.
      4. Matches the AD users with the Endpoint Status 'Logged-in Users' (eps_os_LoggedInUsers) value:
           - Enabled AD users WITHOUT a Forcepoint agent
           - Enabled AD users WITH a Forcepoint agent
           - Users with an agent whose machine has not connected to Forcepoint for a long time (default 30+ days)
           - Machines with more than one logged-on user
           - Forcepoint users not found in AD
      5. Saves the result to the desktop as CSV.

    User filter: (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))
                   (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
    (ENABLED users only; disabled accounts, groups, computers and contacts are excluded).

    Author: FIRAT AYDIN

.EXAMPLE
    .\ForcepointAgentCoverage.en.ps1

.EXAMPLE
    .\ForcepointAgentCoverage.en.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa

.EXAMPLE
    .\ForcepointAgentCoverage.en.ps1 -AdServer DC01.company.local -AdUseCredential -AdSearchBase "OU=Users,DC=company,DC=local"
#>

[CmdletBinding()]
param(
    [string]$SqlServerInstance = '',

    [string]$SqlDatabaseName = 'wbsn-data-security',

    [ValidateSet('Windows', 'SqlLogin')]
    [string]$SqlAuthMode = 'Windows',

    [string]$SqlUserName = '',

    # DC name/IP (empty = the server's domain is discovered automatically)
    [string]$AdServer = '',

    # OU path of the users (prompted if not given; empty = whole domain;
    # multiple OUs separated by ';'; the domain is appended automatically if DC= is omitted)
    [string]$AdSearchBase = '',

    # Skip the connection menu and prompt for a different domain account directly
    # (if not given, the screen offers 1 = current session / 2 = different account)
    [switch]$AdUseCredential,

    # "Not seen for a long time" threshold (days) for users with an agent
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

# Runs the given SQL with sqlcmd and returns the output lines. Throws on error.
function Invoke-FpSql {
    param([Parameter(Mandatory)] [string]$Sql)

    $sqlCmdExe = Get-Command 'sqlcmd.exe' -ErrorAction SilentlyContinue
    if (-not $sqlCmdExe) { throw 'sqlcmd.exe was not found in PATH (SQL Server Command Line Utilities or SSMS required).' }

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
                $script:SecurePassword = Read-Host -Prompt "SQL Server password ($SqlUserName)" -AsSecureString
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
        throw "sqlcmd failed (exit code $exitCode). $($errLines -join ' | ')"
    }
    return ,@($lines | Where-Object { $_.Trim() -ne '' })
}

# Reads the Endpoint Status records (SELECT only).
function Get-FpEndpointStatus {
    $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NULL OR OBJECT_ID('PA_DYNAMIC_STATUS_PROPS','U') IS NULL
BEGIN
    SELECT 'ERROR|PA_DYNAMIC_STATUS / PA_DYNAMIC_STATUS_PROPS tables were not found.';
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

# Returns the ENABLED user accounts in AD (read-only, no RSAT required).
# Computer accounts also have person/user in objectClass, so they are separated with
# objectCategory=person and !(objectClass=computer).
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
        throw 'Could not read domain information (RootDSE). If the server is not a domain member, use -AdServer and -AdUseCredential.'
    }
    $base = $domainDn
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        # The 'LDAP://' / 'LDAP://server/' prefix is removed; the domain DN is appended if DC= is omitted.
        $base = ($SearchBase.Trim() -replace '^LDAP://(?:[^/]+/)?', '').Trim()
        if ($base -notmatch '(^|,)\s*DC=') { $base = "$base,$domainDn" }
    }
    $dcName = [string]$rootDse.Properties['dnsHostName'].Value

    $root = & $newEntry "$prefix$base"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    # ENABLED accounts only: accounts with the userAccountControl ACCOUNTDISABLE (2) bit are filtered out by LDAP.
    $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.PageSize = 1000   # paged read for more than 1000 users
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

# Converts an AD/LDAP error into a readable message (checks the HRESULT in the inner exception chain).
function Get-AdErrorText {
    param([System.Exception]$Exception)
    $ex = $Exception
    while ($ex) {
        switch ($ex.HResult) {
            -2147023570 { return 'Wrong username or password (or the account is locked/disabled).' }          # 0x8007052E
            -2147016646 { return 'Server is unreachable. Check the DC name and LDAP (389) access.' }            # 0x8007203A
            -2147016694 { return 'Domain / DC not found. If the server is not a domain member, enter the DC or domain name.' } # 0x8007200A
            -2147024891 { return 'Access denied. The account has no permission to read AD.' }                  # 0x80070005
            -2147016656 { return 'OU path not found. Check the path (e.g. OU=Users,DC=company,DC=local).' }    # 0x80072030
            -2147016654 { return 'Invalid OU path format. Example: OU=Users,DC=company,DC=local' }             # 0x80072032
        }
        if (-not $ex.InnerException) { break }
        $ex = $ex.InnerException
    }
    return $Exception.Message
}

# Reads the DC/domain, username and password of a different domain account from the screen.
function Read-AdCredential {
    param([string]$DefaultServer = '')
    $srvPrompt = if ($DefaultServer) { "DC or domain name [$DefaultServer]" } else { 'DC or domain name (e.g. dc01.company.local or company.local, empty = automatic)' }
    $srv = (Read-Host -Prompt $srvPrompt).Trim()
    if ($srv -eq '') { $srv = $DefaultServer }
    $user = (Read-Host -Prompt 'AD username (DOMAIN\user or user@company.local)').Trim()
    if ($user -eq '') { return $null }
    $pass = Read-Host -Prompt "AD password ($user)" -AsSecureString
    return [pscustomobject]@{
        Server     = $srv
        Credential = New-Object System.Management.Automation.PSCredential($user, $pass)
    }
}

# Reads the OU path of the users from the screen (empty = whole domain, multiple OUs separated by ';').
function Read-AdSearchBase {
    $dcPart = 'DC=company,DC=local'
    if ($env:USERDNSDOMAIN) { $dcPart = (@($env:USERDNSDOMAIN.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object { "DC=$_" }) -join ',') }
    Write-Host ''
    Write-Host 'Enter the OU path of the users (leave empty to search the whole domain).'
    Write-Host "  Example        : OU=Users,$dcPart" -ForegroundColor DarkGray
    Write-Host "  Sub-OU example : OU=Finance,OU=Users,$dcPart" -ForegroundColor DarkGray
    Write-Host '  Multiple OUs   : separate with a semicolon (;). If DC= is omitted, the domain is appended.' -ForegroundColor DarkGray
    Write-Host '  (OU path: ADUC > OU > Properties > Attribute Editor > distinguishedName)' -ForegroundColor DarkGray
    return (Read-Host -Prompt 'OU path').Trim()
}

# Asks for the AD connection type and the OU path, connects; on error or an empty result offers
# to retry with a different account or a different OU. Results of multiple OUs are merged (unique by DN).
# Returns the result in Get-AdUserList format on success, $null if cancelled.
function Connect-AdInteractive {
    param(
        [string]$Server = '',
        [string]$SearchBase = '',
        [switch]$UseCredential
    )
    $askCred = [bool]$UseCredential
    if (-not $askCred) {
        Write-Host 'Select the AD (LDAP) connection type:'
        Write-Host "  1 = Connect with the current Windows session (default: $env:USERDOMAIN\$env:USERNAME)"
        Write-Host '  2 = Connect with a different domain account (username/password)'
        Write-Host '  0 = Cancel'
        $c = (Read-Host -Prompt 'Your choice [1]').Trim()
        if ($c -eq '0') { return $null }
        $askCred = ($c -eq '2')
    }

    # If -AdSearchBase was not given, the OU path is asked on screen.
    if ([string]::IsNullOrWhiteSpace($SearchBase)) { $SearchBase = Read-AdSearchBase }

    $cred = $null
    $maxAttempts = 3
    try {
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            if ($askCred) {
                $conn = Read-AdCredential -DefaultServer $Server
                if (-not $conn) { Write-Host 'No username entered.' -ForegroundColor DarkYellow; return $null }
                $Server = $conn.Server
                $cred = $conn.Credential
                $askCred = $false
            }
            $who = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current session)" }
            $bases = @($SearchBase -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            if ($bases.Count -eq 0) { $bases = @('') }
            $currentBase = ''
            try {
                $users = New-Object System.Collections.Generic.List[object]
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                $baseTexts = New-Object System.Collections.Generic.List[string]
                $first = $null
                foreach ($b in $bases) {
                    $currentBase = if ($b) { $b } else { '(whole domain)' }
                    $r = Get-AdUserList -Server $Server -SearchBase $b -Credential $cred
                    if (-not $first) { $first = $r }
                    [void]$baseTexts.Add($r.SearchBase)
                    $cnt = 0
                    foreach ($u in @($r.Users)) { if ($seen.Add([string]$u.DistinguishedName)) { [void]$users.Add($u); $cnt++ } }
                    if ($bases.Count -gt 1) { Write-Host ("  {0} : {1} users" -f $r.SearchBase, $cnt) -ForegroundColor DarkGray }
                }
                if ($users.Count -gt 0) {
                    return [pscustomobject]@{
                        DomainDn   = $first.DomainDn
                        SearchBase = ($baseTexts -join ' ; ')
                        DcName     = $first.DcName
                        Users      = $users.ToArray()
                    }
                }
                Write-Host "Connected to AD but no users were returned ($who, OU: $SearchBase). The OU path may be wrong or the account may not have read permission." -ForegroundColor Yellow
            }
            catch {
                Write-Host "AD connection / query FAILED ($who, OU: $currentBase): $(Get-AdErrorText -Exception $_.Exception)" -ForegroundColor Red
            }

            if ($attempt -ge $maxAttempts) {
                Write-Host "No attempts left ($maxAttempts)." -ForegroundColor DarkYellow
                return $null
            }
            Write-Host ''
            Write-Host '  1 = Retry with a different domain account'
            Write-Host '  2 = Change the OU path and retry'
            Write-Host '  0 = Cancel'
            $sel = (Read-Host -Prompt 'Your choice [1]').Trim()
            if ($sel -eq '0') { return $null }
            if ($sel -eq '2') { $SearchBase = Read-AdSearchBase }
            else { $askCred = $true }
        }
    }
    finally { $cred = $null }
    return $null
}

# Splits the Endpoint Status 'Logged-in Users' value into account names.
# Supports 'DOMAIN\user', 'user@domain.local' and multiple users separated by
# comma/semicolon; the domain part is removed.
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

# Compares AD users with Endpoint Status users and reports the result.
# Matching: SamAccountName, the part of the UPN before @, and DisplayName (case-insensitive).
function Invoke-AdComparison {
    param([object[]]$Endpoints, [object]$Ad)

    # Forcepoint user name -> endpoint list
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $fpIndex = New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp)
    $noUserEndpoints = 0
    # Endpoints where more than one user is logged on (one agent, multiple users)
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
            FpAgent           = if ($hits.Count -gt 0) { 'Yes' } else { 'No' }
            FpMachines        = (@($hits | ForEach-Object { $_.Hostname } | Sort-Object -Unique) -join ', ')
            SharedMachine     = if ($sharedHits.Count -gt 0) { 'Yes' } elseif ($hits.Count -gt 0) { 'No' } else { '' }
            FpLastSeenDays    = $minDays
            NotSeenLongTime   = if ($null -ne $minDays -and $minDays -ge $StaleDays) { 'Yes' } elseif ($hits.Count -gt 0) { 'No' } else { '' }
            AdLastLogon       = $u.LastLogon
            UserPrincipalName = $u.UserPrincipalName
            DistinguishedName = $u.DistinguishedName
        })
    }

    $all = $report.ToArray()
    $missing = @($all | Where-Object { $_.FpAgent -eq 'No' } | Sort-Object SamAccountName)
    $matched = @($all | Where-Object { $_.FpAgent -eq 'Yes' } | Sort-Object SamAccountName)
    $stale = @($matched | Where-Object { $_.NotSeenLongTime -eq 'Yes' } | Sort-Object FpLastSeenDays -Descending)

    Write-Section -Title 'AD USER SUMMARY AND FORCEPOINT AGENT STATUS'
    [pscustomobject]@{
        'Scope'                              = 'Enabled AD users'
        'AD Count'                           = $all.Count
        'With FP agent'                      = $matched.Count
        'Without agent'                      = $missing.Count
        "Agent, not seen $StaleDays+ days"   = $stale.Count
    } | Format-Table -AutoSize | Out-Host

    $color = if ($missing.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("ENABLED users without a visible Forcepoint agent: {0}" -f $missing.Count) -ForegroundColor $color
    Write-Host ("{0} enabled users with an FP agent are logged on to {1} different machines in total." -f $matched.Count, $matchedHosts.Count) -ForegroundColor White
    if ($stale.Count -gt 0) {
        Write-Host ("Users with an agent whose machine has not connected to Forcepoint for {0}+ days: {1} (details below)" -f $StaleDays, $stale.Count) -ForegroundColor Yellow
    }
    if ($sharedEps.Count -gt 0) {
        Write-Host ("Machines with more than one logged-on user (shared): {0} (details below)" -f $sharedEps.Count) -ForegroundColor Yellow
    }
    if ($noUserEndpoints -gt 0) {
        Write-Host ("Endpoints with an empty user value: {0} (their users cannot be matched)" -f $noUserEndpoints) -ForegroundColor DarkYellow
    }
    Write-Host 'NOTE: Matching uses the Endpoint Status ''Logged-in Users'' field. Users with an installed agent who are not logged on at the moment may appear as "No".' -ForegroundColor DarkGray

    Write-Section -Title "ENABLED AD USERS WITHOUT A FORCEPOINT AGENT ($($missing.Count))"
    if ($missing.Count -gt 0) {
        $missing | Format-Table @{ L = 'User'; E = { $_.SamAccountName } },
                                @{ L = 'Full Name'; E = { $_.DisplayName } },
                                @{ L = 'E-mail'; E = { $_.Mail } },
                                @{ L = 'AD Last Logon'; E = { $_.AdLastLogon } } -AutoSize | Out-Host
    }
    else { Write-Host 'All enabled AD users matched the Forcepoint Endpoint Status list.' -ForegroundColor Green }

    Write-Section -Title "ENABLED AD USERS WITH A FORCEPOINT AGENT ($($matched.Count))"
    if ($matched.Count -gt 0) {
        $matched | Format-Table @{ L = 'User'; E = { $_.SamAccountName } },
                                @{ L = 'Full Name'; E = { $_.DisplayName } },
                                @{ L = 'FP Machine(s)'; E = { $_.FpMachines } },
                                @{ L = 'Shared'; E = { $_.SharedMachine } },
                                @{ L = 'FP Last Seen (days)'; E = { $_.FpLastSeenDays }; A = 'Right' } -AutoSize | Out-Host
    }
    else { Write-Host 'No matching users.' -ForegroundColor DarkYellow }

    # Agent present but the machine has not connected to Forcepoint for a long time: the agent may not be working.
    Write-Section -Title "USERS WITH AN AGENT NOT SEEN FOR $StaleDays+ DAYS ($($stale.Count))"
    if ($stale.Count -gt 0) {
        Write-Host 'These users'' machines have not connected to Forcepoint for a long time; the agent may be removed or broken, or the machine may be unused.' -ForegroundColor DarkGray
        $stale | Format-Table @{ L = 'User'; E = { $_.SamAccountName } },
                              @{ L = 'Full Name'; E = { $_.DisplayName } },
                              @{ L = 'FP Machine(s)'; E = { $_.FpMachines } },
                              @{ L = 'FP Last Seen (days)'; E = { $_.FpLastSeenDays }; A = 'Right' },
                              @{ L = 'AD Last Logon'; E = { $_.AdLastLogon } } -AutoSize | Out-Host
    }
    else { Write-Host "The machines of all users with an agent connected to Forcepoint within the last $StaleDays days." -ForegroundColor Green }

    # More than one user on the same machine: one agent covers several users.
    Write-Section -Title "MACHINES WITH MORE THAN ONE LOGGED-ON USER ($($sharedEps.Count))"
    if ($sharedEps.Count -gt 0) {
        Write-Host 'On these machines one Forcepoint agent covers several users; each user is counted separately as "with agent" above.' -ForegroundColor DarkGray
        $sharedEps | Sort-Object @{ E = { $_.Names.Count }; Descending = $true }, @{ E = { $_.Endpoint.Hostname } } | ForEach-Object {
            $labels = foreach ($n in $_.Names) {
                if ($adByKey.ContainsKey($n)) {
                    $dn = [string]$adByKey[$n].DisplayName
                    if ($dn) { "$n ($dn)" } else { $n }
                }
                else { "$n (not in AD)" }
            }
            [pscustomobject]@{
                Hostname          = $_.Endpoint.Hostname
                IP                = $_.Endpoint.IpAddress
                'User Count'      = $_.Names.Count
                'Logged-on Users' = ($labels -join ', ')
                'Days'            = $_.Endpoint.DaysAgo
            }
        } | Format-Table -AutoSize | Out-Host
    }
    else { Write-Host 'No machine has more than one logged-on user.' -ForegroundColor Green }

    # Users in Forcepoint without a match in AD (local account, other domain, etc.)
    $fpOnly = @($fpIndex.Keys | Where-Object { -not $adKeySet.Contains($_) } | Sort-Object)
    Write-Section -Title "FORCEPOINT USERS NOT FOUND IN AD ($($fpOnly.Count))"
    if ($fpOnly.Count -gt 0) {
        Write-Host '(May be local accounts, accounts disabled in AD, another domain, or users outside the OU.)' -ForegroundColor DarkGray
        $fpOnly | ForEach-Object {
            [pscustomobject]@{ 'FP User' = $_; 'Machine(s)' = (@($fpIndex[$_] | ForEach-Object { $_.Hostname } | Sort-Object -Unique) -join ', ') }
        } | Format-Table -AutoSize | Out-Host
    }
    else { Write-Host 'All Forcepoint users were found in AD.' -ForegroundColor Green }

    $csv = Join-Path ([Environment]::GetFolderPath('Desktop')) ("Forcepoint_Agent_Coverage_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $all | Sort-Object FpAgent, SamAccountName |
        Select-Object SamAccountName, DisplayName, Mail, FpAgent, FpMachines, SharedMachine, FpLastSeenDays, NotSeenLongTime, AdLastLogon, UserPrincipalName, DistinguishedName |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Report CSV saved: $csv" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------------
# 1) SQL connection
# ------------------------------------------------------------------------------------
Write-Section -Title 'FORCEPOINT DLP - AGENT COVERAGE REPORT (read-only)'

if ([string]::IsNullOrWhiteSpace($SqlServerInstance)) {
    $SqlServerInstance = Read-Host -Prompt 'SQL Server name (e.g. SERVERNAME or SERVERNAME\INSTANCE)'
}
if (-not $PSBoundParameters.ContainsKey('SqlAuthMode')) {
    Write-Host ''
    Write-Host 'Select authentication type:'
    Write-Host '  1 = Windows authentication (default, uses the current session)'
    Write-Host '  2 = SQL Server authentication (username/password)'
    $authChoice = Read-Host -Prompt 'Your choice [1]'
    if ($authChoice.Trim() -eq '2') { $SqlAuthMode = 'SqlLogin' }
}
if ($SqlAuthMode -eq 'SqlLogin' -and [string]::IsNullOrWhiteSpace($SqlUserName)) {
    $SqlUserName = Read-Host -Prompt 'SQL Server username'
}

try {
    $endpoints = Get-FpEndpointStatus
}
catch {
    Write-Host "SQL Server connection / query FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "SQL Server connection: SUCCESS ($SqlServerInstance / $SqlDatabaseName)" -ForegroundColor Green

# ------------------------------------------------------------------------------------
# 2) Short agent summary (informational)
# ------------------------------------------------------------------------------------
Write-Section -Title 'AGENT SUMMARY'
Write-Host ("Total agents in Endpoint Status       : {0}" -f @($endpoints).Count) -ForegroundColor White
foreach ($t in $script:Thresholds) {
    $cnt = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $t }).Count
    $c = if ($cnt -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("Agents not reporting for {0,2}+ days      : {1}" -f $t, $cnt) -ForegroundColor $c
}
Write-Host '(Informational only. Use the ForcepointAgentCleanup script to list/delete stale records.)' -ForegroundColor DarkGray

if (@($endpoints).Count -eq 0) {
    Write-Host ''
    Write-Host 'There are no agents in the Endpoint Status list; nothing to compare.' -ForegroundColor DarkYellow
    exit 0
}

# ------------------------------------------------------------------------------------
# 3) AD connection + comparison
# ------------------------------------------------------------------------------------
Write-Section -Title 'ACTIVE DIRECTORY CONNECTION'
$ad = Connect-AdInteractive -Server $AdServer -SearchBase $AdSearchBase -UseCredential:$AdUseCredential
if (-not $ad) {
    Write-Host ''
    Write-Host 'Could not connect to AD or cancelled; no report was created.' -ForegroundColor DarkYellow
    exit 1
}
$dcText = if ($ad.DcName) { $ad.DcName } else { '(automatic)' }
Write-Host "AD connection: SUCCESS (DC: $dcText)" -ForegroundColor Green
Write-Host "Search base  : $($ad.SearchBase)" -ForegroundColor DarkGray

Invoke-AdComparison -Endpoints $endpoints -Ad $ad

Write-Host 'Report completed. Nothing was deleted or changed in SQL or AD.' -ForegroundColor Green
