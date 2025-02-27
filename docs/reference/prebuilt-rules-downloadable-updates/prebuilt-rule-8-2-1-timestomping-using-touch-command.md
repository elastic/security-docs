---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-timestomping-using-touch-command.html
---

# Timestomping using Touch Command [prebuilt-rule-8-2-1-timestomping-using-touch-command]

Timestomping is an anti-forensics technique which is used to modify the timestamps of a file, often to mimic files that are in the same folder.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Defense Evasion

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1822]



## Rule query [_rule_query_2112]

```js
process where event.type == "start" and
 process.name : "touch" and user.id != "0" and
 process.args : ("-r", "-t", "-a*","-m*") and
 not process.args : ("/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal on Host
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Timestomp
    * ID: T1070.006
    * Reference URL: [https://attack.mitre.org/techniques/T1070/006/](https://attack.mitre.org/techniques/T1070/006/)



