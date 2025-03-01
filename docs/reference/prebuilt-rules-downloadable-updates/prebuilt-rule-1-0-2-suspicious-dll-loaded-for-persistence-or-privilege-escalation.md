---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-dll-loaded-for-persistence-or-privilege-escalation.html
---

# Suspicious DLL Loaded for Persistence or Privilege Escalation [prebuilt-rule-1-0-2-suspicious-dll-loaded-for-persistence-or-privilege-escalation]

Identifies the loading of a non Microsoft-signed DLL that is missing on a default Windows install (phantom DLL) or one that can be loaded from a different location by a native Windows process. This may be abused to persist or elevate privileges via privileged file write vulnerabilities.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://itm4n.github.io/windows-dll-hijacking-clarified/](https://itm4n.github.io/windows-dll-hijacking-clarified/)
* [http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html](http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.md)
* [https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.md)
* [https://shellz.club/edgegdi-dll-for-persistence-and-lateral-movement/](https://shellz.club/edgegdi-dll-for-persistence-and-lateral-movement/)
* [https://windows-internals.com/faxing-your-way-to-system/](https://windows-internals.com/faxing-your-way-to-system/)
* [http://waleedassar.blogspot.com/2013/01/wow64logdll.html](http://waleedassar.blogspot.com/2013/01/wow64logdll.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Privilege Escalation

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1663]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1927]

```js
library where dll.name :
  (
  "wlbsctrl.dll",
  "wbemcomn.dll",
  "WptsExtensions.dll",
  "Tsmsisrv.dll",
  "TSVIPSrv.dll",
  "Msfte.dll",
  "wow64log.dll",
  "WindowsCoreDeviceInfo.dll",
  "Ualapi.dll",
  "wlanhlp.dll",
  "phoneinfo.dll",
  "EdgeGdi.dll",
  "cdpsgshims.dll",
  "windowsperformancerecordercontrol.dll",
  "diagtrack_win.dll"
  ) and
not (dll.code_signature.subject_name : ("Microsoft Windows", "Microsoft Corporation") and dll.code_signature.status : "trusted")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: DLL Side-Loading
    * ID: T1574.002
    * Reference URL: [https://attack.mitre.org/techniques/T1574/002/](https://attack.mitre.org/techniques/T1574/002/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: DLL Search Order Hijacking
    * ID: T1574.001
    * Reference URL: [https://attack.mitre.org/techniques/T1574/001/](https://attack.mitre.org/techniques/T1574/001/)



