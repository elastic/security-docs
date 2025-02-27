---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-microsoft-exchange-worker-spawning-suspicious-processes.html
---

# Microsoft Exchange Worker Spawning Suspicious Processes [prebuilt-rule-8-3-3-microsoft-exchange-worker-spawning-suspicious-processes]

Identifies suspicious processes being spawned by the Microsoft Exchange Server worker process (w3wp). This activity may indicate exploitation activity or access to an existing web shell backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities)
* [https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289](https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Initial Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3142]



## Rule query [_rule_query_3663]

```js
process where event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
  process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



