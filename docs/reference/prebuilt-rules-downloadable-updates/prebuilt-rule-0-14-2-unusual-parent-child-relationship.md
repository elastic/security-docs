---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-unusual-parent-child-relationship.html
---

# Unusual Parent-Child Relationship [prebuilt-rule-0-14-2-unusual-parent-child-relationship]

Identifies Windows programs run from unexpected parent processes. This could indicate masquerading or other strange activity on a system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/sbousseaden/Slides/blob/master/Hunting%20MindMaps/PNG/Windows%20Processes%20TH.map.png](https://github.com/sbousseaden/Slides/blob/master/Hunting%20MindMaps/PNG/Windows%20Processes%20TH.map.png)
* [https://www.andreafortuna.org/2017/06/15/standard-windows-processes-a-brief-reference/](https://www.andreafortuna.org/2017/06/15/standard-windows-processes-a-brief-reference/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1484]

```js
process where event.type in ("start", "process_started") and
process.parent.name != null and
 (
   /* suspicious parent processes */
   (process.name:"autochk.exe" and not process.parent.name:"smss.exe") or
   (process.name:("fontdrvhost.exe", "dwm.exe") and not process.parent.name:("wininit.exe", "winlogon.exe")) or
   (process.name:("consent.exe", "RuntimeBroker.exe", "TiWorker.exe") and not process.parent.name:"svchost.exe") or
   (process.name:"SearchIndexer.exe" and not process.parent.name:"services.exe") or
   (process.name:"SearchProtocolHost.exe" and not process.parent.name:("SearchIndexer.exe", "dllhost.exe")) or
   (process.name:"dllhost.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"smss.exe" and not process.parent.name:("System", "smss.exe")) or
   (process.name:"csrss.exe" and not process.parent.name:("smss.exe", "svchost.exe")) or
   (process.name:"wininit.exe" and not process.parent.name:"smss.exe") or
   (process.name:"winlogon.exe" and not process.parent.name:"smss.exe") or
   (process.name:("lsass.exe", "LsaIso.exe") and not process.parent.name:"wininit.exe") or
   (process.name:"LogonUI.exe" and not process.parent.name:("wininit.exe", "winlogon.exe")) or
   (process.name:"services.exe" and not process.parent.name:"wininit.exe") or
   (process.name:"svchost.exe" and not process.parent.name:("MsMpEng.exe", "services.exe")) or
   (process.name:"spoolsv.exe" and not process.parent.name:"services.exe") or
   (process.name:"taskhost.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"taskhostw.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"userinit.exe" and not process.parent.name:("dwm.exe", "winlogon.exe")) or
   (process.name:("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") and not process.parent.name:"svchost.exe") or
   /* suspicious child processes */
   (process.parent.name:("SearchProtocolHost.exe", "taskhost.exe", "csrss.exe") and not process.name:("werfault.exe", "wermgr.exe", "WerFaultSecure.exe")) or
   (process.parent.name:"autochk.exe" and not process.name:("chkdsk.exe", "doskey.exe", "WerFault.exe")) or
   (process.parent.name:"smss.exe" and not process.name:("autochk.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "WerFault.exe")) or
   (process.parent.name:"wermgr.exe" and not process.name:("WerFaultSecure.exe", "wermgr.exe", "WerFault.exe")) or
   (process.parent.name:"conhost.exe" and not process.name:("mscorsvw.exe", "wermgr.exe", "WerFault.exe", "WerFaultSecure.exe"))
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Process Hollowing
    * ID: T1055.012
    * Reference URL: [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)



