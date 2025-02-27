---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-suspicious-process-creation-calltrace.html
---

# Suspicious Process Creation CallTrace [prebuilt-rule-8-3-1-suspicious-process-creation-calltrace]

Identifies when a process is created and immediately accessed from an unknown memory code region and by the same parent process. This may indicate a code injection or hollowing attempt.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2665]

```js
sequence by host.id with maxspan=1m
  [process where event.code == "1" and
   /* sysmon process creation */
   process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "eqnedt32.exe", "fltldr.exe",
                          "mspub.exe", "msaccess.exe","cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe",
                          "mshta.exe", "wmic.exe", "cmstp.exe", "msxsl.exe") and

   /* noisy FP patterns */
   not (process.parent.name : "EXCEL.EXE" and process.executable : "?:\\Program Files\\Microsoft Office\\root\\Office*\\ADDINS\\*.exe") and
   not (process.executable : "?:\\Windows\\splwow64.exe" and process.args in ("8192", "12288") and process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")) and
   not (process.parent.name : "rundll32.exe" and process.parent.args : ("?:\\WINDOWS\\Installer\\MSI*.tmp,zzzzInvokeManagedCustomActionOutOfProc", "--no-sandbox")) and
   not (process.executable :
            ("?:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\msedgewebview2.exe",
             "?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
             "?:\\Windows\\SysWOW64\\DWWIN.EXE") and
        process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")) and
   not (process.parent.name : "regsvr32.exe" and process.parent.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*"))
   ] by process.parent.entity_id, process.entity_id
  [process where event.code == "10" and
   /* Sysmon process access event from unknown module */
   winlog.event_data.CallTrace : "*UNKNOWN*"] by process.entity_id, winlog.event_data.TargetProcessGUID
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



