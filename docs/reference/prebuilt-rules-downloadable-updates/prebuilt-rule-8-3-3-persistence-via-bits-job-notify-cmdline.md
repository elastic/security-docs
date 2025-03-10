---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-persistence-via-bits-job-notify-cmdline.html
---

# Persistence via BITS Job Notify Cmdline [prebuilt-rule-8-3-3-persistence-via-bits-job-notify-cmdline]

An adversary can use the Background Intelligent Transfer Service (BITS) SetNotifyCmdLine method to execute a program that runs after a job finishes transferring data or after a job enters a specified state in order to persist on a system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/2019/10/30/persistence-bits-jobs/](https://pentestlab.blog/2019/10/30/persistence-bits-jobs/)
* [https://docs.microsoft.com/en-us/windows/win32/api/bits1_5/nf-bits1_5-ibackgroundcopyjob2-setnotifycmdline](https://docs.microsoft.com/en-us/windows/win32/api/bits1_5/nf-bits1_5-ibackgroundcopyjob2-setnotifycmdline)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-setnotifycmdline](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-setnotifycmdline)
* [https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-2](https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-2)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3189]



## Rule query [_rule_query_3732]

```js
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.parent.args : "BITS" and
  not process.executable :
              ("?:\\Windows\\System32\\WerFaultSecure.exe",
               "?:\\Windows\\System32\\WerFault.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\WINDOWS\\system32\\directxdatabaseupdater.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)



