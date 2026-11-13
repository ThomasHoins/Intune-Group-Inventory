# Intune Group Inventory

A read-only PowerShell script that inventories how Microsoft Entra ID groups are used by Microsoft Intune objects. It reports direct and nested group usage, group membership counts, assignment filters, Intune RBAC role assignments, and possible deletion candidates for manual review.

The script makes **GET requests only**. It does not modify Intune or Entra ID.

## Requirements

- PowerShell 7.0 or later
- Microsoft Graph permissions listed below
- The `Microsoft.Graph.Authentication` PowerShell module
- The `ImportExcel` module for Excel output (optional; CSV files are still generated if it is unavailable)

Install the modules for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module ImportExcel -Scope CurrentUser
```

The script requests these Microsoft Graph permissions (delegated or application permissions; admin consent is required):

- `Group.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementRBAC.Read.All`
- `DeviceManagementServiceConfig.Read.All`

## Usage

Run the script and sign in when prompted:

```powershell
.\Get-IntuneGroupInventory.ps1
```

Connect to Graph separately, then reuse the existing connection:

```powershell
Connect-MgGraph -Scopes 'Group.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All','DeviceManagementRBAC.Read.All','DeviceManagementServiceConfig.Read.All'
.\Get-IntuneGroupInventory.ps1 -NoConnect
```

Use device-code sign-in:

```powershell
.\Get-IntuneGroupInventory.ps1 -UseDeviceCode
```

By default, Excel export is enabled. To generate only CSV files:

```powershell
.\Get-IntuneGroupInventory.ps1 -ExportExcel:$false
```

The script caches the group inventory and direct memberships locally per tenant for 24 hours. A fresh cache avoids repeating the initial group and membership requests. To refresh them from Graph:

```powershell
.\Get-IntuneGroupInventory.ps1 -ScanGroups:$true
```

The cache is stored under the current user's local application data folder in `IntuneGroupInventory`. Other Intune objects are still queried from Graph on each run.

Specify a tenant, output directory, CSV delimiter, or maximum nested-group depth:

```powershell
.\Get-IntuneGroupInventory.ps1 -TenantId '<tenant-id>' -OutputPath 'C:\Temp\IntuneAnalysis' -CsvDelimiter ',' -MaxNestingDepth 10
```

List the endpoints and permissions used by the script without running the inventory:

```powershell
.\Get-IntuneGroupInventory.ps1 -ListEndpoints
```

## Output

Unless `-OutputPath` is specified, output is written to a timestamped `IntuneGroupAnalysis_<timestamp>` folder under the current user's Documents folder. The script creates:

- `GroupSummary.csv` — one summary row per group, including membership counts and possible deletion-candidate status
- `GroupUsage.csv` — direct and indirect usage details
- `GroupMembership.csv` — nested group relationships
- `AnalysisErrors.csv` — warnings, errors, checks, and known limitations
- `AnalysisLog.txt` — run progress and summary
- `IntuneGroupAnalysis.xlsx` — when the `ImportExcel` module is installed and Excel export is enabled

The default CSV delimiter is a semicolon. Use `-CsvDelimiter ','` to select a comma.

## Important limitations

- A group with no detected Intune usage is **not necessarily safe to delete**. Review other services and dependencies manually.
- The script does not inventory group usage in Exchange, SharePoint, Teams, Planner, Azure RBAC, Conditional Access, license assignments, Entra app assignments, or third-party applications.
- Some Intune features are not included; consult `AnalysisErrors.csv` for the limitations recorded by the script.
- Intune endpoints are read through the Microsoft Graph beta API, whose schemas can change.
