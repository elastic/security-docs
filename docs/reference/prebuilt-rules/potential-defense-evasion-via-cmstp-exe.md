---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-defense-evasion-via-cmstp-exe.html
---

# Potential Defense Evasion via CMSTP.exe [potential-defense-evasion-via-cmstp-exe]

The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program to install Connection Manager service profiles, which accept installation information file (INF) files. Adversaries may abuse CMSTP to proxy the execution of malicious code by supplying INF files that contain malicious commands.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1218/003/](https://attack.mitre.org/techniques/T1218/003/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_711]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmstp.exe" and process.args == "/s"
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

* Sub-technique:

    * Name: CMSTP
    * ID: T1218.003
    * Reference URL: [https://attack.mitre.org/techniques/T1218/003/](https://attack.mitre.org/techniques/T1218/003/)



