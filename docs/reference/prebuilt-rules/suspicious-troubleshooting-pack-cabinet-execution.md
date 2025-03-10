---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-troubleshooting-pack-cabinet-execution.html
---

# Suspicious Troubleshooting Pack Cabinet Execution [suspicious-troubleshooting-pack-cabinet-execution]

Identifies the execution of the Microsoft Diagnostic Wizard to open a diagcab file from a suspicious path and with an unusual parent process. This may indicate an attempt to execute malicious Troubleshooting Pack Cabinet files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-system.security*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd](https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1090]

```js
process where host.os.type == "windows" and event.action == "start" and
  (process.name : "msdt.exe" or ?process.pe.original_file_name == "msdt.exe") and process.args : "/cab" and
  process.parent.name : (
    "firefox.exe", "chrome.exe", "msedge.exe", "explorer.exe", "brave.exe", "whale.exe", "browser.exe",
    "dragon.exe", "vivaldi.exe", "opera.exe", "iexplore", "firefox.exe", "waterfox.exe", "iexplore.exe",
    "winrar.exe", "winrar.exe", "7zFM.exe", "outlook.exe", "winword.exe", "excel.exe"
  ) and
  process.args : (
    "?:\\Users\\*",
    "\\\\*",
    "http*",
    "ftp://*"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



