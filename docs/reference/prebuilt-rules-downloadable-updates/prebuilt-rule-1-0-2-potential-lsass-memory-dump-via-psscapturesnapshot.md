---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-lsass-memory-dump-via-psscapturesnapshot.html
---

# Potential LSASS Memory Dump via PssCaptureSnapShot [prebuilt-rule-1-0-2-potential-lsass-memory-dump-via-psscapturesnapshot]

Identifies suspicious access to a Local Security Authority Server Service (LSASS) handle via PssCaptureSnapShot where two successive process accesses are performed by the same process and target two different instances of LSASS. This may indicate an attempt to evade detection and dump LSASS memory for credential access.

**Rule type**: threshold

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
* [https://twitter.com/sbousseaden/status/1280619931516747777?lang=en](https://twitter.com/sbousseaden/status/1280619931516747777?lang=en)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1523]

## Config

This is meant to run only on datasources using Elastic Agent 7.14+ since versions prior to that will be missing the threshold
rule cardinality feature.

## Rule query [_rule_query_1760]

```js
event.category:process and event.code:10 and
 winlog.event_data.TargetImage:("C:\\Windows\\system32\\lsass.exe" or
                                 "c:\\Windows\\system32\\lsass.exe" or
                                 "c:\\Windows\\System32\\lsass.exe")
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



