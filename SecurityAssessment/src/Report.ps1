<#
    Report.ps1
    Renders findings into a self-contained HTML report (inline CSS, no external
    dependencies) and optional JSON/CSV exports.
#>

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function New-InventoryTable {
    <# Renders an array of uniform pscustomobjects as an HTML table. #>
    param([object[]]$Rows, [string]$Caption)
    if (-not $Rows -or $Rows.Count -eq 0) { return '' }
    $cols = $Rows[0].PSObject.Properties.Name
    $head = ($cols | ForEach-Object { "<th>$(ConvertTo-HtmlEncoded $_)</th>" }) -join ''
    $body = foreach ($r in $Rows) {
        '<tr>' + (($cols | ForEach-Object { "<td>$(ConvertTo-HtmlEncoded ([string]$r.$_))</td>" }) -join '') + '</tr>'
    }
    @"
<h2 class="inv-h">$(ConvertTo-HtmlEncoded $Caption)</h2>
<table class="inv">
 <thead><tr>$head</tr></thead>
 <tbody>$($body -join "`n")</tbody>
</table>
"@
}

function New-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)][string]$Path,
        [string]$Environment = 'Assessed Environment',
        [hashtable]$Context
    )

    $sevColor = @{ Critical='#b00020'; High='#e65100'; Medium='#f9a825'; Low='#1976d2'; Info='#607d8b' }
    $statusColor = @{ Fail='#b00020'; Pass='#2e7d32'; NotAssessed='#9e9e9e'; Error='#6a1b9a' }
    $gradeColor = switch ($Summary.Grade) { 'A'{'#2e7d32'} 'B'{'#558b2f'} 'C'{'#f9a825'} 'D'{'#e65100'} default {'#b00020'} }

    $rows = foreach ($f in (Sort-FindingsByRisk -Findings $Findings)) {
        $fw = ($f.Frameworks.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ' &bull; '
        $affected = if ($f.AffectedItems.Count) {
            '<div class="affected"><strong>Affected:</strong> ' + (ConvertTo-HtmlEncoded (($f.AffectedItems | Select-Object -First 25) -join ', ')) + '</div>'
        } else { '' }
        @"
<tr class="status-$($f.Status)">
  <td><span class="badge" style="background:$($statusColor[$f.Status])">$($f.Status)</span></td>
  <td><span class="badge" style="background:$($sevColor[$f.Severity])">$($f.Severity)</span></td>
  <td class="id">$(ConvertTo-HtmlEncoded $f.Id)</td>
  <td>
    <div class="title">$(ConvertTo-HtmlEncoded $f.Title)</div>
    <div class="cat">$(ConvertTo-HtmlEncoded $f.Category)</div>
    $(if ($f.Evidence) { '<div class="evidence">' + (ConvertTo-HtmlEncoded $f.Evidence) + '</div>' })
    $affected
    <details><summary>Rationale &amp; remediation</summary>
      <p><strong>Why it matters:</strong> $(ConvertTo-HtmlEncoded $f.Rationale)</p>
      <p><strong>Recommendation:</strong> $(ConvertTo-HtmlEncoded $f.Remediation)</p>
      <p class="fw">$fw</p>
    </details>
  </td>
</tr>
"@
    }

    # --- Infrastructure & specifications section -----------------------------
    $inventoryHtml = ''
    if ($Context) {
        if ($Context.Inventory -and $Context.Inventory.Servers) {
            $inventoryHtml += New-InventoryTable -Rows @($Context.Inventory.Servers) -Caption 'Servers'
        }
        if ($Context.Exchange -and $Context.Exchange.Servers) {
            $exRows = @($Context.Exchange.Servers | Select-Object Name,
                @{ N='Version'; E={ $_.AdminDisplayVersion } }, Roles, Edition,
                @{ N='Mailbox DBs (org)'; E={ $Context.Exchange.MailboxDatabases } })
            $inventoryHtml += New-InventoryTable -Rows $exRows -Caption 'Exchange'
        }
        if ($Context.SQL) {
            $sqlRows = @([pscustomobject]@{
                Instance  = $Context.SQL.Instance
                Version   = $Context.SQL.Version
                Edition   = $Context.SQL.Edition
                AuthMode  = if ($Context.SQL.WindowsAuthOnly) { 'Windows only' } else { 'Mixed mode' }
                Databases = $Context.SQL.DatabaseCount
            })
            $inventoryHtml += New-InventoryTable -Rows $sqlRows -Caption 'SQL Server'
        }
        if ($inventoryHtml) {
            $inventoryHtml = '<h1 class="sec">Infrastructure &amp; Specifications</h1>' + $inventoryHtml +
                             '<h1 class="sec">Findings</h1>'
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report - $(ConvertTo-HtmlEncoded $Environment)</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;color:#212121;background:#f5f5f5}
 header{background:#1a237e;color:#fff;padding:24px 32px}
 header h1{margin:0;font-size:22px} header .sub{opacity:.8;font-size:13px;margin-top:4px}
 .wrap{max-width:1100px;margin:0 auto;padding:24px 32px}
 .cards{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}
 .card{background:#fff;border-radius:10px;padding:18px 22px;box-shadow:0 1px 3px rgba(0,0,0,.12);flex:1;min-width:120px}
 .card .n{font-size:30px;font-weight:700} .card .l{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px}
 .grade{background:$gradeColor;color:#fff}
 table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.12)}
 th{background:#eceff1;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;color:#555}
 td{padding:12px;border-top:1px solid #eee;vertical-align:top;font-size:14px}
 .badge{color:#fff;padding:2px 9px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap}
 .id{font-family:Consolas,monospace;color:#555;font-size:12px}
 .title{font-weight:600} .cat{color:#888;font-size:12px;margin-top:2px}
 .evidence{margin-top:6px;font-size:13px;color:#444;background:#f9f9f9;padding:6px 8px;border-left:3px solid #bbb;border-radius:3px}
 .affected{margin-top:6px;font-size:12px;color:#666}
 details{margin-top:8px} summary{cursor:pointer;color:#1565c0;font-size:13px}
 details p{font-size:13px;margin:6px 0} .fw{color:#888;font-size:12px}
 tr.status-Pass{opacity:.7} footer{color:#888;font-size:12px;padding:20px 32px;text-align:center}
 h1.sec{font-size:17px;color:#1a237e;margin:28px 0 4px;border-bottom:2px solid #c5cae9;padding-bottom:6px}
 h2.inv-h{font-size:13px;color:#555;text-transform:uppercase;letter-spacing:.5px;margin:18px 0 6px}
 table.inv td,table.inv th{font-size:13px;padding:8px 10px;white-space:normal}
 table.inv{margin-bottom:8px}
</style></head><body>
<header>
  <h1>Security Posture Assessment</h1>
  <div class="sub">$(ConvertTo-HtmlEncoded $Environment) &bull; generated $($Summary.GeneratedAt.ToString('yyyy-MM-dd HH:mm'))</div>
</header>
<div class="wrap">
 <div class="cards">
  <div class="card grade"><div class="n">$($Summary.Grade) ($($Summary.Score))</div><div class="l">Posture score</div></div>
  <div class="card"><div class="n" style="color:#b00020">$($Summary.Critical)</div><div class="l">Critical</div></div>
  <div class="card"><div class="n" style="color:#e65100">$($Summary.High)</div><div class="l">High</div></div>
  <div class="card"><div class="n" style="color:#f9a825">$($Summary.Medium)</div><div class="l">Medium</div></div>
  <div class="card"><div class="n" style="color:#1976d2">$($Summary.Low)</div><div class="l">Low</div></div>
  <div class="card"><div class="n" style="color:#2e7d32">$($Summary.Passed)</div><div class="l">Passed</div></div>
  <div class="card"><div class="n" style="color:#9e9e9e">$($Summary.NotAssessed)</div><div class="l">Not assessed</div></div>
 </div>
 $inventoryHtml
 <table>
  <thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Finding</th></tr></thead>
  <tbody>
  $($rows -join "`n")
  </tbody>
 </table>
</div>
<footer>Generated by SecurityAssessment (PowerShell). Findings map to CIS, Microsoft Security Baselines, NIST 800-53 and ASD Essential 8. Read-only assessment - verify before remediating.</footer>
</body></html>
"@

    $html | Out-File -FilePath $Path -Encoding utf8
    $Path
}
