---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-tcc-bypass-via-mounted-apfs-snapshot-access.html
---

# TCC Bypass via Mounted APFS Snapshot Access [prebuilt-rule-8-3-3-tcc-bypass-via-mounted-apfs-snapshot-access]

Identifies the use of the mount_apfs command to mount the entire file system through Apple File System (APFS) snapshots as read-only and with the noowners flag set. This action enables the adversary to access almost any file in the file system, including all user data and files protected by Apple’s privacy framework (TCC).

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://theevilbit.github.io/posts/cve_2020_9771/](https://theevilbit.github.io/posts/cve_2020_9771/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion
* CVE_2020_9771

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3427]

```js
event.category : process and event.type : (start or process_started) and process.name : mount_apfs and
  process.args : (/System/Volumes/Data and noowners)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Direct Volume Access
    * ID: T1006
    * Reference URL: [https://attack.mitre.org/techniques/T1006/](https://attack.mitre.org/techniques/T1006/)



