---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-via-microsoft-dotnet-clickonce-host.html
---

# Execution via Microsoft DotNet ClickOnce Host [execution-via-microsoft-dotnet-clickonce-host]

Identifies the execution of DotNet ClickOnce installer via Dfsvc.exe trampoline. Adversaries may take advantage of ClickOnce to proxy execution of malicious payloads via trusted Microsoft processes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_334]

```js
sequence by user.id with maxspan=5s
 [process where host.os.type == "windows" and event.action == "start" and
  process.name : "rundll32.exe" and process.command_line : ("*dfshim*ShOpenVerbApplication*", "*dfshim*#*")]
 [network where host.os.type == "windows" and process.name : "dfsvc.exe"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)



