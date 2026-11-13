#Requires -Version 7.0
<#
.VERSION
    1.1.0

.HISTORY
    1.1.0 - Added a tenant-specific 24-hour group and membership cache with a forced-refresh switch.
    1.0.0 - Initial version with English documentation, Documents-folder output, and Excel export enabled by default.

.SYNOPSIS
    Analyzes read-only which Entra ID groups are used by which Intune objects.

.DESCRIPTION
    Process (object-based, not group-based):
      1. Load and classify all Entra ID groups (basis for evaluation).
      2. Load direct members of each group (users / devices / groups).
      3. Read all Intune object types from the catalog ($Catalog) and evaluate the assignments
         (/assignments) for each object. In addition, RBAC (role assignments including scope groups)
         and scope tag auto-assignments.
      4. Resolve nested groups starting from directly used groups
         (indirect usage, strictly separated from direct usage).
      5. Statistics, deletion candidate hints, plausibility checks, export.

    The script makes ONLY GET requests. It writes nothing to Intune or Entra ID.

    Required Graph permissions (delegated or application, each only *.Read.All,
    all require admin consent):
      Group.Read.All
      DeviceManagementConfiguration.Read.All
      DeviceManagementApps.Read.All
      DeviceManagementRBAC.Read.All
      DeviceManagementServiceConfig.Read.All

.PARAMETER OutputPath
    Target folder (default: the user's Documents folder\IntuneGroupAnalysis_<timestamp>).
.PARAMETER TenantId
    Optional: tenant for Connect-MgGraph.
.PARAMETER NoConnect
    No sign-in is performed; only an existing Graph connection is used.
.PARAMETER UseDeviceCode
    Device code sign-in instead of browser.
.PARAMETER ExportExcel
    Export to Excel (enabled by default; requires the ImportExcel module; without the module only CSVs are generated).
.PARAMETER CsvDelimiter
    CSV delimiter (default ';' for German Excel; ',' is possible).
.PARAMETER MaxNestingDepth
    Maximum nesting depth for group resolution (default 10).
.PARAMETER ListEndpoints
    Displays only the endpoint/permission overview and exits the script.
.PARAMETER ScanGroups
    Forces an online refresh of the groups and their direct memberships, ignoring the local cache. Use -ScanGroups:$true.

.EXAMPLE
    .\Get-IntuneGroupInventory.ps1
.EXAMPLE
    Connect-MgGraph -Scopes 'Group.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All','DeviceManagementRBAC.Read.All','DeviceManagementServiceConfig.Read.All'
    .\Get-IntuneGroupInventory.ps1 -NoConnect
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TenantId,
    [switch]$NoConnect,
    [switch]$UseDeviceCode,
    [switch]$ExportExcel = $true,
    [ValidateSet(';', ',')][string]$CsvDelimiter = ';',
    [ValidateRange(1, 25)][int]$MaxNestingDepth = 10,
    [switch]$ListEndpoints,
    [switch]$ScanGroups
)

$ErrorActionPreference = 'Stop'
$GraphRoot = 'https://graph.microsoft.com'
$RequiredScopes = @(
    'Group.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All',
    'DeviceManagementRBAC.Read.All',
    'DeviceManagementServiceConfig.Read.All'
)

#region Catalog of Intune object types --------------------------------------------------------
function New-Entry {
    param(
        [string]$Name, [string]$Category, [string]$Path, [string]$Label, [string]$Permission,
        [switch]$UseOdataType, [switch]$Optional, [string]$UsageOverride, [string]$Note
    )
    [pscustomobject]@{
        Name = $Name; Category = $Category; Path = $Path; ApiVersion = 'beta'; Label = $Label
        Permission = $Permission; UseOdataType = [bool]$UseOdataType; Optional = [bool]$Optional
        UsageOverride = $UsageOverride; Note = $Note
    }
}
$pApps = 'DeviceManagementApps.Read.All'
$pCfg = 'DeviceManagementConfiguration.Read.All'
$pSvc = 'DeviceManagementServiceConfig.Read.All'
$pRbac = 'DeviceManagementRBAC.Read.All'

$Catalog = @(
    New-Entry 'mobileApps' 'Applications' 'deviceAppManagement/mobileApps' 'App' $pApps -UseOdataType
    New-Entry 'mobileAppConfigurations' 'Applications' 'deviceAppManagement/mobileAppConfigurations' 'App Configuration Policy (managed devices)' $pApps -UseOdataType
    New-Entry 'targetedManagedAppConfigurations' 'Applications' 'deviceAppManagement/targetedManagedAppConfigurations' 'App Configuration Policy (managed apps)' $pApps
    New-Entry 'deviceConfigurations' 'Device configuration' 'deviceManagement/deviceConfigurations' 'Configuration Profile' $pCfg -UseOdataType
    New-Entry 'configurationPolicies' 'Device configuration / Endpoint Security' 'deviceManagement/configurationPolicies' 'Configuration Policy' $pCfg
    New-Entry 'groupPolicyConfigurations' 'Device configuration' 'deviceManagement/groupPolicyConfigurations' 'Administrative Template' $pCfg
    New-Entry 'deviceCompliancePolicies' 'Compliance' 'deviceManagement/deviceCompliancePolicies' 'Compliance Policy' $pCfg -UseOdataType
    New-Entry 'intents' 'Endpoint Security' 'deviceManagement/intents' 'Endpoint Security Policy / Security Baseline (intent)' $pCfg
    New-Entry 'deviceManagementScripts' 'Scripts' 'deviceManagement/deviceManagementScripts' 'PowerShell Script' $pCfg
    New-Entry 'deviceShellScripts' 'Scripts' 'deviceManagement/deviceShellScripts' 'macOS Shell Script' $pCfg
    New-Entry 'deviceCustomAttributeShellScripts' 'Scripts' 'deviceManagement/deviceCustomAttributeShellScripts' 'macOS Custom Attribute Script' $pCfg -Optional
    New-Entry 'deviceHealthScripts' 'Scripts' 'deviceManagement/deviceHealthScripts' 'Remediation Script (Proactive Remediation)' $pCfg
    New-Entry 'windowsFeatureUpdateProfiles' 'Windows Update' 'deviceManagement/windowsFeatureUpdateProfiles' 'Windows Feature Update Policy' $pCfg
    New-Entry 'windowsQualityUpdateProfiles' 'Windows Update' 'deviceManagement/windowsQualityUpdateProfiles' 'Windows Quality Update Policy' $pCfg
    New-Entry 'windowsQualityUpdatePolicies' 'Windows Update' 'deviceManagement/windowsQualityUpdatePolicies' 'Windows Quality Update Policy (new)' $pCfg -Optional
    New-Entry 'windowsDriverUpdateProfiles' 'Windows Update' 'deviceManagement/windowsDriverUpdateProfiles' 'Windows Driver Update Policy' $pCfg -Optional
    New-Entry 'windowsAutopilotDeploymentProfiles' 'Autopilot / Enrollment' 'deviceManagement/windowsAutopilotDeploymentProfiles' 'Autopilot Deployment Profile' $pSvc
    New-Entry 'deviceEnrollmentConfigurations' 'Autopilot / Enrollment' 'deviceManagement/deviceEnrollmentConfigurations' 'Enrollment Configuration' $pSvc -UseOdataType
    New-Entry 'iosManagedAppProtections' 'App Protection' 'deviceAppManagement/iosManagedAppProtections' 'App Protection Policy (iOS)' $pApps
    New-Entry 'androidManagedAppProtections' 'App Protection' 'deviceAppManagement/androidManagedAppProtections' 'App Protection Policy (Android)' $pApps
    New-Entry 'windowsManagedAppProtections' 'App Protection' 'deviceAppManagement/windowsManagedAppProtections' 'App Protection Policy (Windows)' $pApps
    New-Entry 'mdmWindowsInformationProtectionPolicies' 'App Protection' 'deviceAppManagement/mdmWindowsInformationProtectionPolicies' 'Windows Information Protection (MDM)' $pApps -Optional
    New-Entry 'windowsInformationProtectionPolicies' 'App Protection' 'deviceAppManagement/windowsInformationProtectionPolicies' 'Windows Information Protection (MAM)' $pApps -Optional
    New-Entry 'policySets' 'Other' 'deviceAppManagement/policySets' 'Policy Set' $pApps
    New-Entry 'termsAndConditions' 'Other' 'deviceManagement/termsAndConditions' 'Terms and Conditions' $pSvc
    New-Entry 'intuneBrandingProfiles' 'Other' 'deviceManagement/intuneBrandingProfiles' 'Company Portal Branding Profile' $pSvc -Optional
    New-Entry 'roleScopeTags' 'RBAC' 'deviceManagement/roleScopeTags' 'Scope Tag' $pRbac -UsageOverride 'Other' -Note 'Scope-tag auto-assignment (the group automatically receives this scope tag)'
)

if ($ListEndpoints) {
    $Catalog | Select-Object Name, Category, @{n = 'Endpoint'; e = { "$($_.ApiVersion)/$($_.Path)" } }, Permission, Optional |
        Format-Table -AutoSize
    'Additional: beta/deviceManagement/roleDefinitions + /roleAssignments (RBAC, DeviceManagementRBAC.Read.All)'
    'Additional: beta/deviceManagement/assignmentFilters (filter names, DeviceManagementConfiguration.Read.All)'
    'Additional: v1.0/groups and v1.0/groups/{id}/members (Group.Read.All)'
    return
}
#endregion

#region State, logging -----------------------------------------------------------------------
if (-not $OutputPath) {
    $documentsPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    $OutputPath = Join-Path $documentsPath ('IntuneGroupAnalysis_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$LogFile = Join-Path $OutputPath 'AnalysisLog.txt'
$RunStart = Get-Date

$script:Errors = [System.Collections.Generic.List[object]]::new()
$script:UsageRaw = [System.Collections.Generic.List[object]]::new()
$script:MembershipRows = [System.Collections.Generic.List[object]]::new()
$script:Groups = [System.Collections.Generic.List[object]]::new()
$script:GroupById = @{}
$script:MemberInfo = @{}
$script:Filters = @{}
$script:ScanStats = [ordered]@{}
$script:StepDurations = [System.Collections.Generic.List[object]]::new()
$script:ObjectsWithoutAssignmentInfo = [System.Collections.Generic.List[object]]::new()
$script:BlockingReasons = [System.Collections.Generic.List[string]]::new()
$script:NestedIncompleteRoots = [System.Collections.Generic.HashSet[string]]::new()
$script:DuplicatesRemoved = 0
$script:GroupsLoadedFromCache = $false

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    switch ($Level) {
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    Add-Content -Path $LogFile -Value $line -Encoding utf8
}

function Add-AnalysisError {
    param(
        [ValidateSet('Error', 'Warning', 'Info')][string]$Severity,
        [string]$Category, [string]$Scope, [string]$Message,
        [string]$Url, $StatusCode, [string]$ObjectId, [string]$ObjectName
    )
    $script:Errors.Add([pscustomobject][ordered]@{
            Timestamp  = (Get-Date).ToString('s')
            Severity   = $Severity
            Category   = $Category
            Scope      = $Scope
            ObjectId   = $ObjectId
            ObjectName = $ObjectName
            StatusCode = $StatusCode
            Url        = $Url
            Message    = $Message
        })
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Log "START: $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Action }
    catch {
        Write-Log "Step '$Name' ended with an error: $($_.Exception.Message)" 'ERROR'
        Add-AnalysisError -Severity Error -Category 'StepFailure' -Scope $Name -Message $_.Exception.Message
        $script:BlockingReasons.Add("Step '$Name' failed")
    }
    finally {
        $sw.Stop()
        $script:StepDurations.Add([pscustomobject]@{ Step = $Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
        Write-Log ("END: {0} (Duration {1:N1} s)" -f $Name, $sw.Elapsed.TotalSeconds)
    }
}
#endregion

#region Graph access --------------------------------------------------------------------------
function Get-GraphErrorInfo {
    param($ErrorRecord)
    $status = $null
    $ex = $ErrorRecord.Exception
    if ($ex.Data -and $ex.Data.Contains('StatusCode')) { $status = $ex.Data['StatusCode'] }
    elseif ($ex.PSObject.Properties['Response'] -and $ex.Response -and $ex.Response.PSObject.Properties['StatusCode']) {
        $status = [int]$ex.Response.StatusCode
    }
    $msg = $ex.Message
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $msg = $ErrorRecord.ErrorDetails.Message }
    $msg = ($msg -replace '\s+', ' ')
    if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' }
    [pscustomobject]@{ StatusCode = $status; Message = $msg }
}

function Invoke-GraphGet {
    # The only function that calls Graph. GET only. Retries on 429/5xx.
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers)
    $maxAttempts = 5
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $p = @{ Method = 'GET'; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($Headers) { $p.Headers = $Headers }
            return Invoke-MgGraphRequest @p
        }
        catch {
            $info = Get-GraphErrorInfo $_
            if ($info.StatusCode -in 429, 502, 503, 504 -and $attempt -lt $maxAttempts) {
                $wait = [math]::Min(60, [math]::Pow(2, $attempt) * 2)
                try {
                    $ra = $_.Exception.Response.Headers.RetryAfter
                    if ($ra -and $ra.Delta) { $wait = [math]::Max($wait, [int]$ra.Delta.TotalSeconds) }
                } catch { }
                Write-Log "HTTP $($info.StatusCode) at $Uri - retry $attempt/$maxAttempts in $wait s" 'WARN'
                Start-Sleep -Seconds $wait
                continue
            }
            $e = [System.Exception]::new("HTTP $($info.StatusCode): $($info.Message)")
            $e.Data['StatusCode'] = $info.StatusCode
            $e.Data['Url'] = $Uri
            $e.Data['RawMessage'] = $info.Message
            throw $e
        }
    }
}

function Get-GraphPaged {
    # Reads all pages (@odata.nextLink). Throws on error; Data['Page'] shows the page.
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    while ($next) {
        $page++
        try { $r = Invoke-GraphGet -Uri $next }
        catch { $_.Exception.Data['Page'] = $page; throw }
        if ($null -ne $r.value) { foreach ($i in $r.value) { $items.Add($i) } }
        $next = $r.'@odata.nextLink'
    }
    return , $items
}

function Get-ScanStatusFromError {
    param($Status, [string]$Message)
    if ($Status -in 401, 403) { return 'Forbidden' }
    if ($Status -eq 404) { return 'NotAvailable' }
    if ($Status -eq 400 -and $Message -match 'not supported|not found|no OData route|licens|ResourceNotFound') { return 'NotAvailable' }
    return 'Failed'
}

function Register-HttpError {
    # Logs a Graph error; returns the derived status (Forbidden/NotAvailable/Failed).
    param($ErrorRecord, [string]$Scope, [string]$Url, [string]$ObjectId, [string]$ObjectName)
    $info = Get-GraphErrorInfo $ErrorRecord
    $page = $ErrorRecord.Exception.Data['Page']
    $status = Get-ScanStatusFromError $info.StatusCode $info.Message
    $category = switch ($status) { 'Forbidden' { 'PermissionDenied' } 'NotAvailable' { 'EndpointNotAvailable' } default { 'HttpError' } }
    if ($page -and $page -gt 1) { $category = 'PaginationError' }
    $sev = if ($status -eq 'NotAvailable') { 'Warning' } else { 'Error' }
    Add-AnalysisError -Severity $sev -Category $category -Scope $Scope -Url $Url -StatusCode $info.StatusCode `
        -ObjectId $ObjectId -ObjectName $ObjectName -Message $info.Message
    Write-Log "$category [$Scope] HTTP $($info.StatusCode) $Url" 'WARN'
    return $status
}

function Initialize-GraphConnection {
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
        catch { throw "Module Microsoft.Graph.Authentication is missing. Installation: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" }
    }
    $ctx = Get-MgContext
    if (-not $ctx) {
        if ($NoConnect) { throw 'No existing Graph connection is available and -NoConnect was set.' }
        $p = @{ Scopes = $RequiredScopes; NoWelcome = $true }
        if ($TenantId) { $p.TenantId = $TenantId }
        if ($UseDeviceCode) { $p.UseDeviceCode = $true }
        Connect-MgGraph @p | Out-Null
        $ctx = Get-MgContext
    }
    $granted = @($ctx.Scopes)
    $missing = @($RequiredScopes | Where-Object {
            $s = $_
            -not ($granted | Where-Object { $_ -eq $s -or $_ -eq ($s -replace '\.Read\.All$', '.ReadWrite.All') })
        })
    if ($missing.Count -gt 0 -and $ctx.AuthType -eq 'Delegated' -and -not $NoConnect) {
        Write-Log "Missing permissions ($($missing -join ', ')) - request them." 'WARN'
        $p = @{ Scopes = $RequiredScopes; NoWelcome = $true }
        if ($TenantId) { $p.TenantId = $TenantId }
        if ($UseDeviceCode) { $p.UseDeviceCode = $true }
        Connect-MgGraph @p | Out-Null
        $ctx = Get-MgContext
        $granted = @($ctx.Scopes)
        $missing = @($RequiredScopes | Where-Object {
                $s = $_
                -not ($granted | Where-Object { $_ -eq $s -or $_ -eq ($s -replace '\.Read\.All$', '.ReadWrite.All') })
            })
    }
    Write-Log "Graph context: Account=$($ctx.Account) AppId=$($ctx.ClientId) Tenant=$($ctx.TenantId) AuthType=$($ctx.AuthType)"
    Write-Log "Detected permissions: $($granted -join ', ')"
    if ($missing.Count -gt 0) {
        $m = "Unrecognized permissions: $($missing -join ', '). Affected queries may fail with HTTP 403 and will be logged as PermissionDenied."
        Write-Log $m 'WARN'
        Add-AnalysisError -Severity Warning -Category 'PermissionMissing' -Scope 'Connect' -Message $m
    }
}
#endregion

#region Groups ---------------------------------------------------------------------------------
function Get-GroupClassification {
    param($g)
    $types = @($g.groupTypes)
    $isUnified = $types -contains 'Unified'
    $isDynamic = ($types -contains 'DynamicMembership') -or (-not [string]::IsNullOrEmpty($g.membershipRule))
    $mail = [bool]$g.mailEnabled
    $sec = [bool]$g.securityEnabled
    $groupType = if ($isUnified) { 'Microsoft 365' }
    elseif ($mail -and $sec) { 'Mail-enabled Security' }
    elseif ($mail) { 'Distribution' }
    elseif ($sec) { 'Security' }
    else { 'Unknown' }
    [pscustomobject]@{
        GroupType      = $groupType
        IsM365Group    = $isUnified
        IsDynamic      = $isDynamic
        # Assumption: In Intune, security groups and M365 groups are assignable. Distribution groups and
        # mail-enabled security groups are not offered in the group picker.
        IsIntuneGroup  = ($groupType -in 'Security', 'Microsoft 365')
        MembershipType = if ($isDynamic) { 'Dynamic' } else { 'Assigned' }
    }
}

function Get-GroupCachePath {
    $ctx = Get-MgContext
    $tenantId = if ($ctx.TenantId) { [string]$ctx.TenantId } elseif ($TenantId) { $TenantId } else { '' }
    if ([string]::IsNullOrWhiteSpace($tenantId)) { return $null }

    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) { return $null }
    $tenantKey = $tenantId -replace '[^a-zA-Z0-9.-]', '_'
    Join-Path $localAppData "IntuneGroupInventory\Groups_$tenantKey.json"
}

function Import-GroupCache {
    if ($ScanGroups) {
        Write-Log 'Group cache bypassed because -ScanGroups was specified.'
        return $false
    }

    $path = Get-GroupCachePath
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }

    try {
        $cache = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        $cacheTime = [datetime]::Parse(
            [string]$cache.CachedAt,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $age = [datetime]::UtcNow - $cacheTime.ToUniversalTime()
        $groupRows = @($cache.Groups)
        $memberRows = @($cache.Members)
        if ($cache.Version -ne 1 -or
            [string]$cache.TenantId -ne [string](Get-MgContext).TenantId -or
            $age -lt [timespan]::Zero -or $age -ge [timespan]::FromDays(1) -or
            $null -eq $cache.Groups -or $null -eq $cache.Members -or
            $groupRows.Count -ne $memberRows.Count) {
            Write-Log 'Group cache is stale or invalid; loading groups and memberships from Graph.'
            return $false
        }

        $membersById = @{}
        foreach ($member in $memberRows) {
            $id = [string]$member.Id
            if (-not $id -or $membersById.ContainsKey($id) -or $member.Status -ne 'OK') {
                Write-Log 'Group cache is incomplete or invalid; loading groups and memberships from Graph.' 'WARN'
                return $false
            }
            $membersById[$id] = $member
        }

        foreach ($group in $groupRows) {
            $id = [string]$group.Id
            if (-not $id -or -not $group.Class -or -not $membersById.ContainsKey($id) -or $script:GroupById.ContainsKey($id)) {
                Write-Log 'Group cache is incomplete or invalid; loading groups and memberships from Graph.' 'WARN'
                return $false
            }
        }

        $memberInfoById = @{}
        foreach ($group in $groupRows) {
            $id = [string]$group.Id
            $member = $membersById[$id]
            $childIds = [System.Collections.Generic.List[string]]::new()
            foreach ($childId in @($member.ChildGroupIds)) { $childIds.Add([string]$childId) }
            $memberInfoById[$id] = [pscustomobject]@{
                Status = [string]$member.Status
                Users = [int]$member.Users
                Devices = [int]$member.Devices
                Groups = [int]$member.Groups
                Other = [int]$member.Other
                ChildGroupIds = $childIds
            }
        }
        foreach ($group in $groupRows) {
            $id = [string]$group.Id
            $script:Groups.Add($group)
            $script:GroupById[$id] = $group
            $script:MemberInfo[$id] = $memberInfoById[$id]
            if ($group.Class.GroupType -eq 'Unknown') {
                Add-AnalysisError -Severity Warning -Category 'UnsupportedGroupType' -Scope 'Groups' -ObjectId $id -ObjectName $group.Name `
                    -Message 'Group type could not be determined unambiguously from groupTypes/mailEnabled/securityEnabled.'
            }
        }

        $script:GroupsLoadedFromCache = $true
        Write-Log "Loaded $($script:Groups.Count) groups and their direct memberships from local cache (age: $([math]::Floor($age.TotalHours)) hours)."
        return $true
    }
    catch {
        Write-Log "Could not read group cache '$path': $($_.Exception.Message). Loading groups and memberships from Graph." 'WARN'
        return $false
    }
}

function Export-GroupCache {
    $path = Get-GroupCachePath
    if (-not $path) {
        Write-Log 'Cannot save group cache because the tenant ID or local application data path is unavailable.' 'WARN'
        return
    }

    $members = foreach ($group in $script:Groups) {
        $info = $script:MemberInfo[$group.Id]
        [pscustomobject]@{
            Id = $group.Id
            Status = $info.Status
            Users = $info.Users
            Devices = $info.Devices
            Groups = $info.Groups
            Other = $info.Other
            ChildGroupIds = @($info.ChildGroupIds)
        }
    }
    $cache = [pscustomobject]@{
        Version = 1
        TenantId = [string](Get-MgContext).TenantId
        CachedAt = [datetime]::UtcNow.ToString('o')
        Groups = @($script:Groups.ToArray())
        Members = @($members)
    }

    try {
        $directory = Split-Path -Parent $path
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $cache | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
        Write-Log "Saved group and membership cache: $path"
    }
    catch {
        Write-Log "Could not save group cache '$path': $($_.Exception.Message)" 'WARN'
    }
}

function Get-AllGroups {
    if (Import-GroupCache) {
        Write-Log "Groups found: $($script:Groups.Count) (M365: $(@($script:Groups | Where-Object { $_.Class.IsM365Group }).Count), dynamic: $(@($script:Groups | Where-Object { $_.Class.IsDynamic }).Count))"
        if ($script:Groups.Count -eq 0) { throw 'No groups found - abort (check Group.Read.All permissions).' }
        return
    }

    $uri = "$GraphRoot/v1.0/groups?" + '$select=id,displayName,description,groupTypes,mail,mailEnabled,securityEnabled,membershipRule,membershipRuleProcessingState,createdDateTime,onPremisesSyncEnabled,isAssignableToRole,resourceProvisioningOptions&$top=999'
    $raw = Get-GraphPaged -Uri $uri
    foreach ($g in $raw) {
        $c = Get-GroupClassification $g
        $id = ([string]$g.id).ToLowerInvariant()
        $obj = [pscustomobject]@{
            Id = $id; Name = [string]$g.displayName; Class = $c
            MembershipRule = [string]$g.membershipRule; RuleState = [string]$g.membershipRuleProcessingState
            Created = $g.createdDateTime; Synced = [bool]$g.onPremisesSyncEnabled
            RoleAssignable = [bool]$g.isAssignableToRole
            IsTeam = (@($g.resourceProvisioningOptions) -contains 'Team')
        }
        $script:Groups.Add($obj)
        $script:GroupById[$id] = $obj
        if ($c.GroupType -eq 'Unknown') {
            Add-AnalysisError -Severity Warning -Category 'UnsupportedGroupType' -Scope 'Groups' -ObjectId $id -ObjectName $obj.Name `
                -Message 'Group type could not be determined unambiguously from groupTypes/mailEnabled/securityEnabled.'
        }
    }
    Write-Log "Groups found: $($script:Groups.Count) (M365: $(@($script:Groups | Where-Object { $_.Class.IsM365Group }).Count), dynamic: $(@($script:Groups | Where-Object { $_.Class.IsDynamic }).Count))"
    if ($script:Groups.Count -eq 0) { throw 'No groups found - abort (check Group.Read.All permissions).' }
}

function Get-AllGroupMembers {
    if ($script:GroupsLoadedFromCache) {
        Write-Log "Using cached direct memberships for $($script:Groups.Count) groups."
        return
    }

    $total = $script:Groups.Count
    $i = 0
    try {
        foreach ($g in $script:Groups) {
            $i++
            Write-Progress -Activity 'Loading group members' -Status "$i of $total groups - $($g.Name)" `
                -PercentComplete ([math]::Floor(($i / $total) * 100))
            $url = "$GraphRoot/v1.0/groups/$($g.Id)/members?" + '$select=id&$top=999'
            $info = [pscustomobject]@{ Status = 'OK'; Users = 0; Devices = 0; Groups = 0; Other = 0; ChildGroupIds = [System.Collections.Generic.List[string]]::new() }
            try {
                foreach ($m in (Get-GraphPaged -Uri $url)) {
                    switch ($m.'@odata.type') {
                        '#microsoft.graph.user' { $info.Users++ }
                        '#microsoft.graph.device' { $info.Devices++ }
                        '#microsoft.graph.group' { $info.Groups++; $info.ChildGroupIds.Add(([string]$m.id).ToLowerInvariant()) }
                        default { $info.Other++ }
                    }
                }
            }
            catch {
                $info.Status = 'Failed'
                [void](Register-HttpError -ErrorRecord $_ -Scope 'GroupMembers' -Url $url -ObjectId $g.Id -ObjectName $g.Name)
            }
            $script:MemberInfo[$g.Id] = $info
        }
    }
    finally {
        Write-Progress -Activity 'Loading group members' -Completed
    }
    $failed = @($script:MemberInfo.Values | Where-Object { $_.Status -ne 'OK' }).Count
    if ($failed -gt 0) { $script:BlockingReasons.Add("Members of $failed group(s) could not be read") }
    else { Export-GroupCache }
}

function Get-AssignmentFilters {
    $url = "$GraphRoot/beta/deviceManagement/assignmentFilters"
    try {
        foreach ($f in (Get-GraphPaged -Uri $url)) {
            $script:Filters[([string]$f.id).ToLowerInvariant()] = [pscustomobject]@{ Name = $f.displayName; Platform = $f.platform }
        }
        Write-Log "Assignment filters found: $($script:Filters.Count)"
    }
    catch { [void](Register-HttpError -ErrorRecord $_ -Scope 'AssignmentFilters' -Url $url) }
}
#endregion

#region Intune objects -------------------------------------------------------------------------
$TypeMap = @{
    win32LobApp = 'Win32 App'; officeSuiteApp = 'Microsoft 365 Apps'; webApp = 'Web App'
    winGetApp = 'Microsoft Store App (new)'; microsoftStoreForBusinessApp = 'Microsoft Store App (legacy)'
    windowsMicrosoftEdgeApp = 'Microsoft Edge App (Windows)'; windowsAppX = 'Windows AppX/MSIX App'
    windowsUniversalAppX = 'Windows Universal AppX App'; windowsMobileMSI = 'Windows MSI LOB App'
    iosStoreApp = 'iOS Store App'; iosVppApp = 'iOS VPP App'; iosLobApp = 'iOS LOB App'
    managedIOSStoreApp = 'iOS Store App (managed)'; managedIOSLobApp = 'iOS LOB App (managed)'
    androidStoreApp = 'Android Store App'; managedAndroidStoreApp = 'Android Store App (managed)'
    androidManagedStoreApp = 'Managed Google Play App'; managedAndroidLobApp = 'Android LOB App (managed)'
    androidLobApp = 'Android LOB App'; macOSDmgApp = 'macOS DMG App'; macOSPkgApp = 'macOS PKG App'
    macOSLobApp = 'macOS LOB App'; macOSMicrosoftEdgeApp = 'Microsoft Edge App (macOS)'
    macOSMicrosoftDefenderApp = 'Microsoft Defender App (macOS)'; macOSOfficeSuiteApp = 'Microsoft 365 Apps (macOS)'
    macOsVppApp = 'macOS VPP App'
    windowsUpdateForBusinessConfiguration = 'Windows Update Ring'
    windows10EnrollmentCompletionPageConfiguration = 'Enrollment Status Page (ESP)'
    deviceEnrollmentPlatformRestrictionsConfiguration = 'Enrollment Restriction (Platform)'
    deviceEnrollmentPlatformRestrictionConfiguration = 'Enrollment Restriction (Platform)'
    deviceEnrollmentLimitConfiguration = 'Enrollment Restriction (Device Limit)'
    deviceEnrollmentWindowsHelloForBusinessConfiguration = 'Windows Hello for Business (Enrollment)'
    windows10CustomConfiguration = 'Configuration Profile (Custom OMA-URI)'
}

function Get-ObjectTypeLabel {
    param($Entry, $o)
    if ($Entry.Name -eq 'configurationPolicies') {
        $fam = [string]$o.templateReference.templateFamily
        if ([string]::IsNullOrEmpty($fam) -or $fam -eq 'none') { return 'Settings Catalog Policy' }
        if ($fam -like 'endpointSecurity*') { return 'Endpoint Security: ' + ($fam -replace '^endpointSecurity', '') }
        if ($fam -eq 'baseline') { return 'Security Baseline' }
        return "Configuration Policy ($fam)"
    }
    if ($Entry.UseOdataType) {
        $raw = ([string]$o.'@odata.type') -replace '^#microsoft\.graph\.', ''
        if ($raw) {
            if ($TypeMap.ContainsKey($raw)) { return $TypeMap[$raw] }
            return "$($Entry.Label) ($raw)"
        }
    }
    return $Entry.Label
}

function Convert-AssignmentTarget {
    param($Assignment)
    $t = $Assignment.target
    $type = [string]$t.'@odata.type'
    $gid = [string]$t.groupId
    if (-not $gid -and $type -like '*scopeTagGroupAssignmentTarget') { $gid = [string]$t.entraObjectId }
    $fid = [string]$t.deviceAndAppManagementAssignmentFilterId
    $ftype = [string]$t.deviceAndAppManagementAssignmentFilterType
    if (-not $fid -or $fid -eq '00000000-0000-0000-0000-000000000000' -or $ftype -eq 'none') { $fid = ''; $ftype = '' }
    elseif ($ftype) { $ftype = (Get-Culture).TextInfo.ToTitleCase($ftype.ToLowerInvariant()) }
    $usage = $null
    $skip = $false
    if ($type -eq '#microsoft.graph.groupAssignmentTarget') { $usage = 'Include' }
    elseif ($type -eq '#microsoft.graph.exclusionGroupAssignmentTarget') { $usage = 'Exclude' }
    elseif ($gid) { $usage = 'Unknown' }
    else { $skip = $true }   # All Users / All Devices / ConfigMgr collections and similar: no Entra group
    [pscustomobject]@{ GroupId = $gid.ToLowerInvariant().Trim('{', '}'); UsageType = $usage; FilterId = $fid.ToLowerInvariant(); FilterType = $ftype; TargetType = $type; Skip = $skip }
}

function New-ScanStat {
    param([string]$Name, [string]$Category, [string]$Permission, [bool]$Optional)
    $s = [pscustomobject]@{
        Name = $Name; Category = $Category; Permission = $Permission; Optional = $Optional; Status = 'OK'
        Listed = 0; Evaluated = 0; Failed = 0; NoAssignments = 0; GroupRefs = 0; NonGroupTargets = 0
    }
    $script:ScanStats[$Name] = $s
    return $s
}

function Add-Usage {
    param([string]$GroupId, [string]$UsageType, [string]$ObjectName, [string]$ObjectId, [string]$ObjectType,
        [string]$Category, [string]$FilterId, [string]$FilterType, [string]$Details)
    $script:UsageRaw.Add([pscustomobject]@{
            GroupId = $GroupId; UsageType = $UsageType; IsDirect = $true; ParentGroupId = ''; RootGroupId = ''; Depth = 0
            ObjectName = $ObjectName; ObjectId = $ObjectId; ObjectType = $ObjectType; ObjectCategory = $Category
            FilterId = $FilterId; FilterType = $FilterType; Details = $Details
        })
}

function Invoke-CatalogScan {
    param($Entry)
    $stat = New-ScanStat $Entry.Name $Entry.Category $Entry.Permission $Entry.Optional
    $base = "$GraphRoot/$($Entry.ApiVersion)/$($Entry.Path)"
    try { $objects = Get-GraphPaged -Uri $base }
    catch {
        $stat.Status = Register-HttpError -ErrorRecord $_ -Scope $Entry.Name -Url $base
        if ($stat.Status -eq 'Forbidden') { Write-Log "Missing permission for $($Entry.Name) ($($Entry.Permission))" 'ERROR' }
        return
    }
    $stat.Listed = $objects.Count
    foreach ($o in $objects) {
        $oid = [string]$o.id
        $oname = if ($o.displayName) { [string]$o.displayName } elseif ($o.name) { [string]$o.name } else { $oid }
        $otype = Get-ObjectTypeLabel $Entry $o
        $aurl = "$base/$oid/assignments"
        try { $assignments = Get-GraphPaged -Uri $aurl }
        catch {
            $stat.Failed++
            [void](Register-HttpError -ErrorRecord $_ -Scope $Entry.Name -Url $aurl -ObjectId $oid -ObjectName $oname)
            $script:ObjectsWithoutAssignmentInfo.Add([pscustomobject]@{ Scope = $Entry.Name; ObjectId = $oid; ObjectName = $oname })
            continue
        }
        $stat.Evaluated++
        if ($assignments.Count -eq 0) { $stat.NoAssignments++; continue }
        foreach ($a in $assignments) {
            $c = Convert-AssignmentTarget $a
            if ($c.Skip) { $stat.NonGroupTargets++; continue }
            $usage = if ($Entry.UsageOverride) { $Entry.UsageOverride } else { $c.UsageType }
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($Entry.Note) { $parts.Add($Entry.Note) }
            if ($c.UsageType -eq 'Unknown') {
                $parts.Add("Unknown target type '$($c.TargetType)' with group reference - usage type cannot be determined")
                Add-AnalysisError -Severity Warning -Category 'UnknownUsageType' -Scope $Entry.Name -ObjectId $oid -ObjectName $oname `
                    -Message "Target type '$($c.TargetType)' cannot be mapped unambiguously (group $($c.GroupId))."
            }
            if ($a.PSObject.Properties['intent'] -and $a.intent) { $parts.Add("Intent=$($a.intent)") }
            if ($a.PSObject.Properties['runRemediationScript']) { $parts.Add("RunRemediationScript=$($a.runRemediationScript)") }
            if ($a.PSObject.Properties['source'] -and $a.source) { $parts.Add("Source=$($a.source)") }
            $parts.Add("AssignmentId=$($a.id)")
            Add-Usage -GroupId $c.GroupId -UsageType $usage -ObjectName $oname -ObjectId $oid -ObjectType $otype `
                -Category $Entry.Category -FilterId $c.FilterId -FilterType $c.FilterType -Details ($parts -join '; ')
            $stat.GroupRefs++
        }
    }
    if ($stat.Failed -gt 0) { $stat.Status = 'PartialFailure' }
    Write-Log ("{0}: Objects={1}, evaluated={2}, failed={3}, no assignments={4}, group references={5}, non-group targets={6}" -f `
            $Entry.Name, $stat.Listed, $stat.Evaluated, $stat.Failed, $stat.NoAssignments, $stat.GroupRefs, $stat.NonGroupTargets)
}

function Invoke-RoleScan {
    $stat = New-ScanStat 'roleDefinitions/roleAssignments' 'RBAC' 'DeviceManagementRBAC.Read.All' $false
    $defUrl = "$GraphRoot/beta/deviceManagement/roleDefinitions"
    try { $defs = Get-GraphPaged -Uri $defUrl }
    catch { $stat.Status = Register-HttpError -ErrorRecord $_ -Scope 'RBAC' -Url $defUrl; return }
    foreach ($d in $defs) {
        $listUrl = "$defUrl/$($d.id)/roleAssignments"
        try { $assigns = Get-GraphPaged -Uri $listUrl }
        catch {
            $stat.Failed++
            [void](Register-HttpError -ErrorRecord $_ -Scope 'RBAC' -Url $listUrl -ObjectId $d.id -ObjectName $d.displayName)
            continue
        }
        foreach ($ra in $assigns) {
            $stat.Listed++
            $detailUrl = "$listUrl/$($ra.id)"
            try { $detail = Invoke-GraphGet -Uri $detailUrl }
            catch {
                $stat.Failed++
                [void](Register-HttpError -ErrorRecord $_ -Scope 'RBAC' -Url $detailUrl -ObjectId $ra.id -ObjectName $ra.displayName)
                $script:ObjectsWithoutAssignmentInfo.Add([pscustomobject]@{ Scope = 'RBAC'; ObjectId = $ra.id; ObjectName = $ra.displayName })
                continue
            }
            $stat.Evaluated++
            $name = "$($d.displayName) / $($detail.displayName)"
            $scopeType = [string]$detail.scopeType
            $sets = @(
                @{ Ids = @($detail.members); Usage = 'Role Assignment'; Text = 'Member group (administrators) of the role assignment' }
                @{ Ids = @($detail.resourceScopes); Usage = 'Scope Group'; Text = 'Scope group (resourceScopes) of the role assignment' }
                @{ Ids = @($detail.scopeMembers); Usage = 'Scope Group'; Text = 'Scope group (scopeMembers) of the role assignment' }
            )
            foreach ($set in $sets) {
                foreach ($gid in $set.Ids) {
                    if ([string]::IsNullOrWhiteSpace([string]$gid)) { continue }
                    $g = ([string]$gid).Trim('{', '}').ToLowerInvariant()
                    if ($g -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { $stat.NonGroupTargets++; continue }
                    Add-Usage -GroupId $g -UsageType $set.Usage -ObjectName $name -ObjectId ([string]$ra.id) -ObjectType 'Intune Role Assignment' `
                        -Category 'RBAC' -FilterId '' -FilterType '' -Details "$($set.Text); Role=$($d.displayName); ScopeType=$scopeType"
                    $stat.GroupRefs++
                }
            }
        }
    }
    if ($stat.Failed -gt 0) { $stat.Status = 'PartialFailure' }
    Write-Log "RBAC: assignments=$($stat.Listed), evaluated=$($stat.Evaluated), failed=$($stat.Failed), group references=$($stat.GroupRefs)"
}
#endregion

#region Nesting ------------------------------------------------------------------------
function Get-GroupName { param([string]$Id) if ($script:GroupById.ContainsKey($Id)) { $script:GroupById[$Id].Name } else { '<not resolvable>' } }

function Resolve-NestedUsage {
    # Direct group relationships (all groups)
    foreach ($g in $script:Groups) {
        $mi = $script:MemberInfo[$g.Id]
        if (-not $mi) { continue }
        foreach ($child in $mi.ChildGroupIds) {
            $script:MembershipRows.Add([pscustomobject][ordered]@{
                    ParentGroupId = $g.Id; ParentGroupName = $g.Name; MemberGroupId = $child; MemberGroupName = (Get-GroupName $child)
                    NestingDepth = 1; Relation = 'Direct'; RootGroupId = ''; RootGroupName = ''; Path = "$($g.Name) > $(Get-GroupName $child)"; PathIds = "$($g.Id) > $child"
                })
        }
    }
    # Indirect usage starting from directly used groups
    $directRows = @($script:UsageRaw | Where-Object { $_.IsDirect })
    $newRows = [System.Collections.Generic.List[object]]::new()
    foreach ($rg in ($directRows | Group-Object GroupId)) {
        $rootId = $rg.Name
        if (-not $script:GroupById.ContainsKey($rootId)) { continue }
        $rootName = Get-GroupName $rootId
        $visited = @{}
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([pscustomobject]@{ Id = $rootId; Depth = 0; Path = @($rootId) })
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            $mi = $script:MemberInfo[$cur.Id]
            if (-not $mi -or $mi.Status -ne 'OK') {
                [void]$script:NestedIncompleteRoots.Add($rootId)
                Add-AnalysisError -Severity Warning -Category 'MembershipUnavailable' -Scope 'NestedGroups' -ObjectId $cur.Id -ObjectName (Get-GroupName $cur.Id) `
                    -Message "Members not readable; nesting below this group (root $rootName / $rootId) is incomplete."
                continue
            }
            foreach ($child in $mi.ChildGroupIds) {
                if ($cur.Path -contains $child) {
                    Add-AnalysisError -Severity Info -Category 'CircularMembership' -Scope 'NestedGroups' -ObjectId $child -ObjectName (Get-GroupName $child) `
                        -Message "Circular membership detected (root $rootName / $rootId, parent $($cur.Id)); branch not followed further."
                    continue
                }
                if ($visited.ContainsKey($child)) {
                    Add-AnalysisError -Severity Info -Category 'MultiplePaths' -Scope 'NestedGroups' -ObjectId $child -ObjectName (Get-GroupName $child) `
                        -Message "Group is reachable via multiple paths from root $rootName / $rootId; only the first (shortest) path is counted."
                    continue
                }
                $depth = $cur.Depth + 1
                if ($depth -gt $MaxNestingDepth) {
                    [void]$script:NestedIncompleteRoots.Add($rootId)
                    Add-AnalysisError -Severity Warning -Category 'MaxDepthReached' -Scope 'NestedGroups' -ObjectId $child -ObjectName (Get-GroupName $child) `
                        -Message "MaxNestingDepth=$MaxNestingDepth reached (root $rootName / $rootId)."
                    continue
                }
                $visited[$child] = $true
                $path = @($cur.Path) + $child
                $pathNames = ($path | ForEach-Object { Get-GroupName $_ }) -join ' > '
                $pathIds = $path -join ' > '
                if (-not $script:GroupById.ContainsKey($child)) {
                    Add-AnalysisError -Severity Warning -Category 'UnresolvedGroupReference' -Scope 'NestedGroups' -ObjectId $child `
                        -Message "Member group $child (root $rootId) is not in the group list; cannot be resolved further."
                }
                if ($depth -ge 2) {
                    $script:MembershipRows.Add([pscustomobject][ordered]@{
                            ParentGroupId = $cur.Id; ParentGroupName = (Get-GroupName $cur.Id); MemberGroupId = $child; MemberGroupName = (Get-GroupName $child)
                            NestingDepth = $depth; Relation = 'Indirect'; RootGroupId = $rootId; RootGroupName = $rootName; Path = $pathNames; PathIds = $pathIds
                        })
                }
                foreach ($r in $rg.Group) {
                    $newRows.Add([pscustomobject]@{
                            GroupId = $child; UsageType = 'Indirect Membership'; IsDirect = $false; ParentGroupId = $cur.Id; RootGroupId = $rootId; Depth = $depth
                            ObjectName = $r.ObjectName; ObjectId = $r.ObjectId; ObjectType = $r.ObjectType; ObjectCategory = $r.ObjectCategory
                            FilterId = $r.FilterId; FilterType = $r.FilterType
                            Details = "Nested member (depth $depth) of group '$rootName' ($rootId), which is used directly as '$($r.UsageType)'. Path: $pathNames"
                        })
                }
                $queue.Enqueue([pscustomobject]@{ Id = $child; Depth = $depth; Path = $path })
            }
        }
    }
    foreach ($n in $newRows) { $script:UsageRaw.Add($n) }
    Write-Log "Indirect usages (before deduplication): $($newRows.Count)"
}
#endregion

#region Evaluation -----------------------------------------------------------------------------
function Get-FinalUsage {
    $seen = @{}
    $final = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $script:UsageRaw) {
        $key = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $r.GroupId, $r.ObjectId, $r.UsageType, $r.IsDirect, $r.ParentGroupId, $r.RootGroupId, $r.FilterId
        if ($r.IsDirect -eq $false) { $key += '|' + $r.Details }   # the same group may appear indirectly through different root usages
        if ($seen.ContainsKey($key)) { $script:DuplicatesRemoved++; continue }
        $seen[$key] = $true
        $final.Add($r)
    }
    $unresolved = @{}
    $out = foreach ($r in $final) {
        $known = $script:GroupById.ContainsKey($r.GroupId)
        if (-not $known -and -not $unresolved.ContainsKey($r.GroupId)) {
            $unresolved[$r.GroupId] = $true
            Add-AnalysisError -Severity Warning -Category 'UnresolvedGroupReference' -Scope 'Usage' -ObjectId $r.GroupId -ObjectName $r.ObjectName `
                -Message "Group ID $($r.GroupId) is referenced by Intune (for example '$($r.ObjectName)'), but is not found in Entra ID (deleted or unreadable)."
        }
        $g = if ($known) { $script:GroupById[$r.GroupId] } else { $null }
        $fname = ''
        if ($r.FilterId) {
            if ($script:Filters.ContainsKey($r.FilterId)) { $fname = $script:Filters[$r.FilterId].Name }
            else {
                $fname = '<not resolvable>'
                Add-AnalysisError -Severity Warning -Category 'UnresolvedFilter' -Scope 'Usage' -ObjectId $r.FilterId -ObjectName $r.ObjectName `
                    -Message "Assignment filter $($r.FilterId) could not be resolved."
            }
        }
        [pscustomobject][ordered]@{
            GroupName            = if ($g) { $g.Name } else { '<not resolvable>' }
            GroupId              = $r.GroupId
            GroupType            = if ($g) { $g.Class.GroupType } else { 'Unknown' }
            IsM365Group          = if ($g) { $g.Class.IsM365Group } else { $false }
            ObjectName           = $r.ObjectName
            ObjectId             = $r.ObjectId
            ObjectType           = $r.ObjectType
            UsageType            = $r.UsageType
            IsDirect             = $r.IsDirect
            ParentGroupId        = $r.ParentGroupId
            AssignmentFilterId   = $r.FilterId
            AssignmentFilterName = $fname
            AssignmentFilterType = $r.FilterType
            Details              = $r.Details
            RootGroupId          = $r.RootGroupId
            NestingDepth         = $r.Depth
            ObjectCategory       = $r.ObjectCategory
        }
    }
    return @($out)
}

function Get-GroupSummary {
    param($Usage)
    $byGroup = $Usage | Group-Object GroupId -AsHashTable -AsString
    if (-not $byGroup) { $byGroup = @{} }

    $blocking = [System.Collections.Generic.List[string]]::new($script:BlockingReasons)
    foreach ($s in $script:ScanStats.Values) {
        if ($s.Status -eq 'OK') { continue }
        if ($s.Optional -and $s.Status -eq 'NotAvailable') { continue }
        $blocking.Add("$($s.Name)=$($s.Status)")
    }
    if ($script:NestedIncompleteRoots.Count -gt 0) { $blocking.Add("Nesting incomplete for $($script:NestedIncompleteRoots.Count) used group(s)") }
    $blockText = ($blocking | Select-Object -Unique) -join '; '

    foreach ($g in ($script:Groups | Sort-Object Name)) {
        $rows = @($byGroup[$g.Id])
        $direct = @($rows | Where-Object { $_ -and $_.IsDirect })
        $indirect = @($rows | Where-Object { $_ -and -not $_.IsDirect })
        $mi = $script:MemberInfo[$g.Id]
        $memOk = $mi -and $mi.Status -eq 'OK'
        $include = @($direct | Where-Object { $_.UsageType -eq 'Include' }).Count
        $exclude = @($direct | Where-Object { $_.UsageType -eq 'Exclude' }).Count
        $other = $direct.Count - $include - $exclude
        $used = ($direct.Count + $indirect.Count) -gt 0

        $notes = [System.Collections.Generic.List[string]]::new()
        if ($g.Class.IsM365Group) { $notes.Add('Microsoft 365 group: Teams/SharePoint/Exchange/Planner were not checked') }
        if ($g.IsTeam) { $notes.Add('Group belongs to a team') }
        if ($g.Synced) { $notes.Add('Synced from local AD (deletion only possible locally)') }
        if ($g.RoleAssignable) { $notes.Add('Role-assignable group (Entra roles possible)') }
        if ($g.Class.IsDynamic -and $g.RuleState -eq 'Paused') { $notes.Add('Dynamic rule paused') }

        $cand = $false
        if ($used) { $reason = "Intune usage found (direct: $($direct.Count), indirect: $($indirect.Count))" }
        elseif ($g.Class.GroupType -eq 'Unknown') { $reason = 'Group type not determinable - not evaluated' }
        elseif (-not $g.Class.IsIntuneGroup) { $reason = "Group type '$($g.Class.GroupType)' is not intended for Intune assignments - no statement about deletability possible (check Exchange/other services)" }
        elseif ($blockText) { $reason = "No Intune usage found, but analysis is incomplete: $blockText" }
        elseif (-not $memOk) { $reason = 'No Intune usage found, but group members could not be read' }
        else {
            $cand = $true
            $reason = 'No direct or indirect Intune usage found in all scanned object types'
            if ($memOk -and ($mi.Users + $mi.Devices + $mi.Groups + $mi.Other) -eq 0) { $reason += '; group has no members' }
            $reason += '; manual review required (other services not examined)'
        }
        if ($notes.Count -gt 0) { $reason += ' | Notes: ' + ($notes -join '; ') }

        [pscustomobject][ordered]@{
            GroupName                   = $g.Name
            GroupId                     = $g.Id
            GroupType                   = $g.Class.GroupType
            IsM365Group                 = $g.Class.IsM365Group
            IsIntuneGroup               = $g.Class.IsIntuneGroup
            IsIntuneUsed                = $used
            MembershipType              = $g.Class.MembershipType
            MemberCount                 = if ($memOk) { $mi.Users + $mi.Devices + $mi.Groups + $mi.Other } else { $null }
            UserMemberCount             = if ($memOk) { $mi.Users } else { $null }
            DeviceMemberCount           = if ($memOk) { $mi.Devices } else { $null }
            GroupMemberCount            = if ($memOk) { $mi.Groups } else { $null }
            OtherMemberCount            = if ($memOk) { $mi.Other } else { $null }
            IntuneObjectCount           = @($direct | Select-Object -ExpandProperty ObjectId -Unique).Count
            IncludeCount                = $include
            ExcludeCount                = $exclude
            OtherUsageCount             = $other
            IndirectUsageCount          = $indirect.Count
            DeletionCandidate           = $cand
            DeletionCandidateReason     = $reason
            MembershipRuleProcessingState = $g.RuleState
            IsSynced                    = $g.Synced
            CreatedDateTime             = $g.Created
        }
    }
}

function Test-Plausibility {
    param($Usage, $Summary)
    # 1) Group count against $count
    try {
        $cnt = Invoke-GraphGet -Uri "$GraphRoot/v1.0/groups/`$count" -Headers @{ ConsistencyLevel = 'eventual' }
        $msg = "Groups: loaded=$($script:Groups.Count), /groups/`$count=$cnt"
        if ([int]$cnt -eq $script:Groups.Count) { Add-AnalysisError -Severity Info -Category 'PlausibilityCheck' -Scope 'GroupCount' -Message "OK - $msg" }
        else { Add-AnalysisError -Severity Warning -Category 'PlausibilityCheck' -Scope 'GroupCount' -Message "DIFFERENCE - $msg" }
        Write-Log $msg
    }
    catch { [void](Register-HttpError -ErrorRecord $_ -Scope 'GroupCount' -Url "$GraphRoot/v1.0/groups/`$count") }
    # 2) Unresolved group references
    $unres = @($Usage | Where-Object { $_.GroupName -eq '<not resolvable>' } | Select-Object -ExpandProperty GroupId -Unique)
    Add-AnalysisError -Severity $(if ($unres.Count) { 'Warning' } else { 'Info' }) -Category 'PlausibilityCheck' -Scope 'UnresolvedGroups' -Message "Unresolved group IDs in usages: $($unres.Count)"
    # 3) Objects without assignment info
    Add-AnalysisError -Severity $(if ($script:ObjectsWithoutAssignmentInfo.Count) { 'Warning' } else { 'Info' }) -Category 'PlausibilityCheck' -Scope 'NoAssignmentInfo' `
        -Message "Objects without evaluable assignment info (request failed): $($script:ObjectsWithoutAssignmentInfo.Count)"
    # 4) Unsupported group types
    $unk = @($script:Groups | Where-Object { $_.Class.GroupType -eq 'Unknown' }).Count
    Add-AnalysisError -Severity $(if ($unk) { 'Warning' } else { 'Info' }) -Category 'PlausibilityCheck' -Scope 'UnsupportedGroupTypes' -Message "Groups with non-determinable type: $unk"
    # 5) Were all objects processed?
    foreach ($s in $script:ScanStats.Values) {
        $ok = ($s.Listed -eq ($s.Evaluated + $s.Failed))
        Add-AnalysisError -Severity $(if ($ok -and $s.Status -eq 'OK') { 'Info' } else { 'Warning' }) -Category 'PlausibilityCheck' -Scope $s.Name `
            -Message "Status=$($s.Status); objects=$($s.Listed); evaluated=$($s.Evaluated); failed=$($s.Failed); without assignments=$($s.NoAssignments)"
    }
    # 6) Duplicates
    Add-AnalysisError -Severity Info -Category 'PlausibilityCheck' -Scope 'Duplicates' -Message "Removed duplicate usage records (key: group/object/usage/direct/parent/root/filter): $($script:DuplicatesRemoved)"
    # 7) Consistency Summary <-> Usage
    $sumDirect = ($Summary | Measure-Object IncludeCount, ExcludeCount, OtherUsageCount -Sum | Measure-Object Sum -Sum).Sum
    $useDirectKnown = @($Usage | Where-Object { $_.IsDirect -and $_.GroupName -ne '<not resolvable>' }).Count
    $okSum = ($sumDirect -eq $useDirectKnown)
    Add-AnalysisError -Severity $(if ($okSum) { 'Info' } else { 'Warning' }) -Category 'PlausibilityCheck' -Scope 'SummaryVsUsage' -Message "Direct usages: Summary=$sumDirect, Usage(known groups)=$useDirectKnown"
}

function Add-KnownLimitations {
    $items = @(
        'Not examined: group usage outside Intune (Exchange, SharePoint, Teams, Planner, Azure RBAC, Conditional Access, license assignment, Entra app assignments, third-party applications). A missing Intune reference does NOT mean a group is unnecessary.'
        'Not examined: Apple enrollment profiles (ADE/DEP, user-initiated), Android enrollment profiles, Cloud PC / Windows 365 provisioning policies, device cleanup rules, Intune Suite/add-ons without assignment structures.'
        'Dynamic groups do not contain groups as members; nesting only affects static (assigned) groups.'
        'Assignments with "All Users", "All Devices", or Configuration Manager collections contain no Entra group reference and are not counted as group usage.'
        'Scope tags themselves are not groups. Only their auto-assignments (group targets) are recorded as usage type "Other".'
        'Intune endpoints are read through the Graph beta API (Microsoft may change beta schemas). Beta properties scopeMembers/scopeType of role assignments are available only there.'
        'Member counts are direct members (users/devices/groups/other). Transitive members are not included in MemberCount.'
    )
    foreach ($i in $items) { Add-AnalysisError -Severity Info -Category 'Limitation' -Scope 'General' -Message $i }
}
#endregion

#region Export ---------------------------------------------------------------------------------
$Columns = @{
    GroupSummary    = @('GroupName', 'GroupId', 'GroupType', 'IsM365Group', 'IsIntuneGroup', 'IsIntuneUsed', 'MembershipType', 'MemberCount', 'UserMemberCount', 'DeviceMemberCount', 'GroupMemberCount', 'OtherMemberCount', 'IntuneObjectCount', 'IncludeCount', 'ExcludeCount', 'OtherUsageCount', 'IndirectUsageCount', 'DeletionCandidate', 'DeletionCandidateReason', 'MembershipRuleProcessingState', 'IsSynced', 'CreatedDateTime')
    GroupUsage      = @('GroupName', 'GroupId', 'GroupType', 'IsM365Group', 'ObjectName', 'ObjectId', 'ObjectType', 'UsageType', 'IsDirect', 'ParentGroupId', 'AssignmentFilterId', 'AssignmentFilterName', 'AssignmentFilterType', 'Details', 'RootGroupId', 'NestingDepth', 'ObjectCategory')
    GroupMembership = @('ParentGroupId', 'ParentGroupName', 'MemberGroupId', 'MemberGroupName', 'NestingDepth', 'Relation', 'RootGroupId', 'RootGroupName', 'Path', 'PathIds')
    AnalysisErrors  = @('Timestamp', 'Severity', 'Category', 'Scope', 'ObjectId', 'ObjectName', 'StatusCode', 'Url', 'Message')
}
$GuidColumns = @('GroupId', 'ObjectId', 'ParentGroupId', 'MemberGroupId', 'RootGroupId', 'AssignmentFilterId', 'PathIds')

function ConvertTo-TextRows {
    # Convert booleans and dates to text (True/False, ISO) so Excel does not reformat them
    param($Rows, [string[]]$Cols)
    foreach ($r in $Rows) {
        $o = [ordered]@{}
        foreach ($c in $Cols) {
            $v = $r.$c
            $o[$c] = if ($v -is [bool]) { $v.ToString() } elseif ($v -is [datetime]) { $v.ToString('s') } elseif ($null -eq $v) { '' } else { [string]$v }
        }
        [pscustomobject]$o
    }
}

function Export-Results {
    param($Summary, $Usage)
    $sets = [ordered]@{
        GroupSummary    = @($Summary)
        GroupUsage      = @($Usage)
        GroupMembership = @($script:MembershipRows)
        AnalysisErrors  = @($script:Errors)
    }
    foreach ($name in $sets.Keys) {
        $path = Join-Path $OutputPath "$name.csv"
        $cols = $Columns[$name]
        $rows = @(ConvertTo-TextRows -Rows $sets[$name] -Cols $cols)
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -Path $path -NoTypeInformation -Delimiter $CsvDelimiter -Encoding utf8BOM
        }
        else {
            ($cols | ForEach-Object { '"' + $_ + '"' }) -join $CsvDelimiter | Set-Content -Path $path -Encoding utf8BOM
        }
        Write-Log "CSV written: $path ($($rows.Count) lines)"
    }
    if ($ExportExcel) {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Log 'Module ImportExcel not installed - Excel export skipped (Install-Module ImportExcel -Scope CurrentUser). CSV files were created.' 'WARN'
            Add-AnalysisError -Severity Warning -Category 'ExcelSkipped' -Scope 'Export' -Message 'ImportExcel not available.'
            return
        }
        try {
            Import-Module ImportExcel -ErrorAction Stop
            $xlsx = Join-Path $OutputPath 'IntuneGroupAnalysis.xlsx'
            if (Test-Path $xlsx) { Remove-Item $xlsx -Force }
            foreach ($name in $sets.Keys) {
                $cols = $Columns[$name]
                $rows = @(ConvertTo-TextRows -Rows $sets[$name] -Cols $cols)
                if ($rows.Count -eq 0) { $rows = @([pscustomobject](@{} + ($cols | ForEach-Object -Begin { $h = [ordered]@{} } -Process { $h[$_] = '' } -End { $h }))) }
                $rows | Export-Excel -Path $xlsx -WorksheetName $name -TableName $name -TableStyle Medium2 -AutoFilter -AutoSize -FreezeTopRow -NoNumberConversion ($cols | Where-Object { $_ -in $GuidColumns })
            }
            Write-Log "Excel written: $xlsx"
        }
        catch {
            Write-Log "Excel export failed: $($_.Exception.Message)" 'ERROR'
            Add-AnalysisError -Severity Error -Category 'ExcelFailed' -Scope 'Export' -Message $_.Exception.Message
        }
    }
}
#endregion

#region Main flow ----------------------------------------------------------------------------
Write-Log "=== Analysis started: $RunStart | Output: $OutputPath ==="
Write-Log 'Mode: read-only access only (GET).'

Invoke-Step 'Graph connection' { Initialize-GraphConnection }
if ($script:BlockingReasons -contains "Step 'Graph connection' failed") { Write-Log 'No Graph connection means the run is not possible.' 'ERROR'; return }

Invoke-Step 'Load Entra groups' { Get-AllGroups }
if ($script:Groups.Count -eq 0) { Write-Log 'No groups - abort.' 'ERROR'; return }

Invoke-Step 'Load group members' { Get-AllGroupMembers }
Invoke-Step 'Load assignment filters' { Get-AssignmentFilters }

foreach ($entry in $Catalog) {
    $e = $entry
    Invoke-Step "Intune scan: $($e.Name)" { Invoke-CatalogScan $e }
}
Invoke-Step 'Intune scan: RBAC (role assignments)' { Invoke-RoleScan }

Invoke-Step 'Resolve nested groups' { Resolve-NestedUsage }

$finalUsage = @()
$summary = @()
Invoke-Step 'Evaluation (Usage, Summary)' {
    $script:finalUsage = Get-FinalUsage
    $script:summary = @(Get-GroupSummary -Usage $script:finalUsage)
}
Invoke-Step 'Plausibility checks' { Test-Plausibility -Usage $script:finalUsage -Summary $script:summary }
Add-KnownLimitations
Invoke-Step 'Export' { Export-Results -Summary $script:summary -Usage $script:finalUsage }

# Final log
$runEnd = Get-Date
Write-Log '--- Result ---'
Write-Log "Groups total: $($script:Groups.Count)"
foreach ($s in $script:ScanStats.Values) {
    Write-Log ("  {0,-45} Status={1,-14} Objects={2,4} evaluated={3,4} failed={4,3} group references={5,4}" -f $s.Name, $s.Status, $s.Listed, $s.Evaluated, $s.Failed, $s.GroupRefs)
}
$dir = @($script:finalUsage | Where-Object { $_.IsDirect }).Count
$ind = @($script:finalUsage | Where-Object { -not $_.IsDirect }).Count
Write-Log "Group usages: direct=$dir, indirect=$ind"
Write-Log "Unevaluated objects (assignment request failed): $($script:ObjectsWithoutAssignmentInfo.Count)"
Write-Log "Not successfully scanned object types: $(@($script:ScanStats.Values | Where-Object { $_.Status -ne 'OK' }).Count)"
Write-Log "Errors: $(@($script:Errors | Where-Object { $_.Severity -eq 'Error' }).Count), warnings: $(@($script:Errors | Where-Object { $_.Severity -eq 'Warning' }).Count)"
Write-Log "Deletion candidates (for information only, manual review!): $(@($script:summary | Where-Object { $_.DeletionCandidate }).Count)"
foreach ($d in $script:StepDurations) { Write-Log ("  Duration {0,-55} {1,7:N1} s" -f $d.Step, $d.Seconds) }
Write-Log ("=== Analysis finished: {0} (Total duration {1:N1} min) ===" -f $runEnd, ($runEnd - $RunStart).TotalMinutes)
# Save the log file again at the end (AnalysisLog.txt is written continuously)
#endregion
