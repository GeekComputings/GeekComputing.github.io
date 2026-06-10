---
layout: post
title:  "Building a Security Posture Assessment Tool in PowerShell"
date:   2026-06-10 09:00:00 -0500
categories: security powershell active-directory
---

Most "security assessment" exercises start the same way: someone opens a
spreadsheet, RDPs into a handful of servers, eyeballs some settings, and writes
down what looks wrong. It doesn't scale, it isn't repeatable, and the findings
are only as good as the memory of whoever ran them.

So I built a small tool to do it properly — a **read-only PowerShell assessment
tool** that walks a Microsoft estate (Windows Server, Active Directory, Exchange
on-prem, SQL Server, and Microsoft 365 / Entra ID), checks it against known-good
baselines, and spits out a prioritised list of gaps with a recommendation for
each one — along with an inventory of the infrastructure it assessed. The
full source lives in [`/SecurityAssessment`]({{ site.baseurl }}/SecurityAssessment)
in this repo.

## Why PowerShell

Every target I care about is Microsoft, and PowerShell is the *native*
administrative interface for all of them — the `ActiveDirectory` module ships on
every domain controller, Exchange has its management shell, and `Microsoft.Graph`
covers Entra ID and Exchange Online. A Python build would mean reimplementing all
of that over WinRM and Graph with extra glue and a runtime to deploy. PowerShell
runs agentless with the credentials an admin already has, and its output objects
map straight onto a findings report. So PowerShell it is.

## The one design decision that matters: checks are data, not code

The temptation with a tool like this is to write a long script full of
`if`/`else` blocks. That rots fast — every new check means editing the core, and
mapping findings to frameworks like CIS or NIST becomes a nightmare.

Instead, the engine is generic and every **check is a self-describing object**:

{% highlight powershell %}
New-AssessmentCheck -Id 'AD-003' -Title 'No accounts with unconstrained delegation' `
    -Category 'Active Directory' -Requires AD -Severity Critical `
    -Frameworks @{ MS='Securing Privileged Access'; NIST='AC-6' } `
    -Rationale 'Unconstrained delegation lets a compromised host impersonate any
                user that authenticates to it, including Domain Admins.' `
    -Remediation 'Replace with constrained or resource-based constrained
                  delegation; mark sensitive accounts as not delegatable.' `
    -Test {
        param($ad)
        $hosts = @($ad.UnconstrainedDelegation)
        @{ Passed = ($hosts.Count -eq 0)
           Evidence = "$($hosts.Count) host(s) with unconstrained delegation."
           AffectedItems = $hosts }
    }
{% endhighlight %}

Adding a check is dropping one of these into a `checks/*.checks.ps1` file. The
engine never changes. Each finding already carries its own severity, framework
references, rationale and remediation, so the report writes itself.

## Three layers

The tool is deliberately boring in structure, which is what makes it easy to
extend:

- **Collectors** gather read-only state from each target into a single
  `$Context` hashtable. Crucially, they degrade gracefully: if the AD module or
  Graph connection isn't there, the collector returns `$null` and those checks
  are reported as *Not Assessed* instead of crashing the run.
- **The engine** runs every check's `-Test` block against the context, then
  computes a weighted posture score (Critical findings hurt far more than Low
  ones).
- **Reporting** renders a self-contained HTML dashboard — no external CSS or JS —
  plus optional JSON and CSV for piping into a SIEM or ticketing system.

## What it checks today

Twenty-six checks across five modules, each mapped to **CIS Benchmarks**,
**Microsoft Security Baselines**, **NIST 800-53** and **ASD Essential 8**:

| Module | What it looks for |
|--------|-------------------|
| Active Directory | KRBTGT password age (Golden Ticket exposure), Domain/Enterprise Admin sprawl, unconstrained delegation, `MachineAccountQuota`, password policy, reversible encryption, LAPS deployment, stale accounts |
| Windows Server | SMBv1, RDP Network Level Authentication, host firewall, legacy TLS/SSL, patch age, local administrator membership |
| Exchange (on-prem) | supported/patched build, basic authentication, externally-exposed ECP |
| M365 / Entra ID | legacy auth blocking, admin MFA enforcement, Global Admin count, Conditional Access baseline |
| SQL Server | supported/patched build, authentication mode, `sa` account state, `xp_cmdshell`, backup recency |

The report doesn't just list gaps — it opens with an **Infrastructure &
Specifications** section: every server's OS, CPU, RAM, disks and uptime, the
Exchange servers with their versions and roles, and the SQL instances with
edition and authentication mode. An assessment is only as credible as its
scope, and this section shows exactly what was looked at.

## Trying it without an environment

You don't need a live domain to see it work. There's a `-Demo` mode backed by
deliberately-imperfect synthetic data:

{% highlight powershell %}
.\Invoke-SecurityAssessment.ps1 -Demo
{% endhighlight %}

```
Loaded 26 checks.
Running in DEMO mode (synthetic data).

Posture score: 9/100 (Grade F)
Critical 4  High 13  Medium 6  Low 1  Passed 2  NotAssessed 0
HTML report: .\reports\assessment-20260610-053954.html
```

The HTML report groups findings by risk, badges them by severity, and tucks the
rationale and remediation behind an expander so the top of the page stays
scannable. You can browse a
[sample report]({{ site.baseurl }}/SecurityAssessment/samples/sample-report.html)
generated from that demo data.

## Where it's going

This is a v1 foundation, not a finished product. Next on the list: live
build/CVE comparison tables for Exchange and Windows, a BloodHound-style summary
of AD attack paths, copy-paste remediation snippets per finding, Linux/SSH
collectors, and scheduled runs that report the delta since last time so you can
actually watch the posture improve.

If you want to follow along or add your own checks, the code is in the
[`SecurityAssessment`]({{ site.baseurl }}/SecurityAssessment) folder of this
site's repo.
