---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-potential-macos-ssh-brute-force-detected.html
---

# Potential macOS SSH Brute Force Detected [prebuilt-rule-8-3-2-potential-macos-ssh-brute-force-detected]

Identifies a high number (20) of macOS SSH KeyGen process executions from the same host. An adversary may attempt a brute force attack to obtain unauthorized access to user accounts.

**Rule type**: threshold

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://themittenmac.com/detecting-ssh-activity-via-process-monitoring/](https://themittenmac.com/detecting-ssh-activity-via-process-monitoring/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2760]

```js
event.category:process and event.type:start and process.name:"sshd-keygen-wrapper" and process.parent.name:launchd
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)



