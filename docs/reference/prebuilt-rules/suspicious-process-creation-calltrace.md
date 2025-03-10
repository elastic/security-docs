---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-process-creation-calltrace.html
---

# Suspicious Process Creation CallTrace [suspicious-process-creation-calltrace]

Identifies when a process is created and immediately accessed from an unknown memory code region and by the same parent process. This may indicate a code injection attempt.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Sysmon

**Version**: 308

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1024]

**Triage and analysis**

**Investigating Suspicious Process Creation CallTrace**

Attackers may inject code into child processes' memory to hide their actual activity, evade detection mechanisms, and decrease discoverability during forensics. This rule looks for a spawned process by Microsoft Office, scripting, and command line applications, followed by a process access event for an unknown memory region by the parent process, which can indicate a code injection attempt.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications, and any spawned child processes.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Inspect the host for suspicious or abnormal behavior in the alert timeframe.
* Create a memory dump of the child process for analysis.

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1075]

```js
sequence by host.id with maxspan=1m
  [process where host.os.type == "windows" and event.code == "1" and
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
  [process where host.os.type == "windows" and event.code == "10" and
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



