---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-potential-lsass-clone-creation-via-psscapturesnapshot.html
---

# Potential LSASS Clone Creation via PssCaptureSnapShot [prebuilt-rule-0-14-3-potential-lsass-clone-creation-via-psscapturesnapshot]

Identifies the creation of an LSASS process clone via PssCaptureSnapShot where the parent process is the initial LSASS process instance. This may indicate an attempt to evade detection and dump LSASS memory for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)
* [https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2](https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1340]

## Config

This is meant to run only on datasources using Windows security event 4688 that captures the process clone creation.

## Rule query [_rule_query_1507]

```js
process where event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



