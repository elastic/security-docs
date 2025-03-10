---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-suspicious-lsass-process-access.html
---

# Suspicious Lsass Process Access [prebuilt-rule-8-7-1-suspicious-lsass-process-access]

Identifies access attempts to LSASS handle, this may indicate an attempt to dump credentials from Lsass memory.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Sysmon Only

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3809]

## Setup

## Rule query [_rule_query_4658]

```js
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and
  not winlog.event_data.GrantedAccess :
                ("0x1000", "0x1400", "0x101400", "0x101000", "0x101001", "0x100000", "0x100040", "0x3200", "0x40", "0x3200") and
  not process.name : ("procexp64.exe", "procmon.exe", "procexp.exe", "Microsoft.Identity.AadConnect.Health.AadSync.Host.ex") and
  not process.executable :
            ("?:\\Windows\\System32\\lsm.exe",
             "?:\\Program Files\\*",
             "?:\\Program Files (x86)\\*",
             "?:\\Windows\\System32\\msiexec.exe",
             "?:\\Windows\\CCM\\CcmExec.exe",
             "?:\\Windows\\system32\\csrss.exe",
             "?:\\Windows\\system32\\wininit.exe",
             "?:\\Windows\\system32\\wbem\\wmiprvse.exe",
             "?:\\Windows\\system32\\MRT.exe",
             "?:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*",
             "?:\\ProgramData\\WebEx\\webex\\*",
             "?:\\Windows\\LTSvc\\LTSVC.exe") and
   not winlog.event_data.CallTrace : ("*mpengine.dll*", "*appresolver.dll*", "*sysmain.dll*")
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



