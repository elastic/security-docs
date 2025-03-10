---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-for-mssql-service-accounts.html
---

# Unusual Process For MSSQL Service Accounts [unusual-process-for-mssql-service-accounts]

Identifies unusual process executions using MSSQL Service accounts, which can indicate the exploitation/compromise of SQL instances. Attackers may exploit exposed MSSQL instances for initial access or lateral movement.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/)
* [https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver16](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver16)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Persistence
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1189]

```js
process where event.type == "start" and host.os.type == "windows" and
  user.name : (
    "SQLSERVERAGENT", "SQLAGENT$*",
    "MSSQLSERVER", "MSSQL$*",
    "MSSQLServerOLAPService",
    "ReportServer*", "MsDtsServer150",
    "MSSQLFDLauncher*",
    "SQLServer2005SQLBrowserUser$*",
    "SQLWriter", "winmgmt"
  ) and user.domain : "NT SERVICE" and
  not (
    (
      process.name : (
        "sqlceip.exe", "sqlservr.exe", "sqlagent.exe",
        "msmdsrv.exe", "ReportingServicesService.exe",
        "MsDtsSrvr.exe", "sqlbrowser.exe", "DTExec.exe",
        "SQLPS.exe", "fdhost.exe", "fdlauncher.exe",
        "SqlDumper.exe", "sqlsqm.exe", "DatabaseMail.exe",
        "ISServerExec.exe", "Microsoft.ReportingServices.Portal.WebHost.exe",
        "bcp.exe", "SQLCMD.exe", "DatabaseMail.exe"
      ) or
      process.executable : (
        "?:\\Windows\\System32\\wermgr.exe",
        "?:\\Windows\\System32\\conhost.exe",
        "?:\\Windows\\System32\\WerFault.exe"
      )
    ) and
    (
      process.code_signature.subject_name : ("Microsoft Corporation", "Microsoft Windows") and
      process.code_signature.trusted == true
    )
  ) and
  not (
    (process.name : "cmd.exe" and process.parent.name : "sqlservr.exe") or
    (process.name : "cmd.exe" and process.parent.name : "forfiles.exe" and process.command_line : "/c echo *")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Exploitation of Remote Services
    * ID: T1210
    * Reference URL: [https://attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: SQL Stored Procedures
    * ID: T1505.001
    * Reference URL: [https://attack.mitre.org/techniques/T1505/001/](https://attack.mitre.org/techniques/T1505/001/)



