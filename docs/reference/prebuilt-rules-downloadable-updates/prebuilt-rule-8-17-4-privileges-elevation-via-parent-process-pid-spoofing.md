---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-privileges-elevation-via-parent-process-pid-spoofing.html
---

# Privileges Elevation via Parent Process PID Spoofing [prebuilt-rule-8-17-4-privileges-elevation-via-parent-process-pid-spoofing]

Identifies parent process spoofing used to create an elevated child process. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6](https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6)
* [https://blog.didierstevens.com/2017/03/20/](https://blog.didierstevens.com/2017/03/20/)
* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4991]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privileges Elevation via Parent Process PID Spoofing**

Parent Process ID (PPID) spoofing is a technique where adversaries manipulate the PPID of a process to disguise its origin, often to bypass security measures or gain elevated privileges. This is particularly concerning in Windows environments where processes can inherit permissions from their parent. The detection rule identifies suspicious process creation patterns, such as unexpected PPID values and elevated user IDs, while filtering out known legitimate processes and trusted signatures, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the process creation event details, focusing on the process.parent.Ext.real.pid and user.id fields to confirm if the PPID spoofing led to privilege escalation to SYSTEM.
* Examine the process.executable and process.parent.executable paths to determine if the process is known or expected in the environment, and check against the list of excluded legitimate processes.
* Investigate the process.code_signature fields to verify if the process is signed by a trusted entity and if the signature is valid, especially if the process is not excluded by the rule.
* Check the historical activity of the involved user.id and process.parent.executable to identify any unusual patterns or recent changes in behavior.
* Correlate the alert with other security events or logs to identify any related suspicious activities or potential lateral movement attempts within the network.

**False positive analysis**

* Processes related to Windows Error Reporting such as WerFault.exe and Wermgr.exe can trigger false positives. These are legitimate system processes and can be excluded by verifying their signatures and paths.
* Logon utilities like Utilman.exe spawning processes such as osk.exe, Narrator.exe, or Magnify.exe may appear suspicious but are often legitimate. Exclude these by confirming their usage context and ensuring they are executed by trusted users.
* Third-party software like TeamViewer, Cisco WebEx, and Dell Inc. may cause false positives due to their legitimate use of process creation. Verify the code signature and trust status to exclude these processes.
* Windows Update processes involving MpSigStub.exe and wuauclt.exe can be mistakenly flagged. Confirm these are part of regular update activities and exclude them based on their known paths and parent processes.
* Remote support and management tools such as LogMeIn, GoToAssist, and Chrome Remote Desktop may be flagged. Ensure these are installed and used by authorized personnel and exclude them by their executable paths.
* Netwrix Corporation’s processes like adcrcpy.exe may be flagged if they are part of legitimate auditing activities. Verify the code signature and exclude these processes if they are part of authorized Netwrix Auditor operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the alert, especially those with spoofed PPIDs or elevated privileges, to stop potential malicious activities.
* Review and revoke any unauthorized user accounts or privileges that may have been created or escalated during the incident.
* Conduct a thorough forensic analysis of the affected system to identify any additional indicators of compromise or persistence mechanisms.
* Restore the system from a known good backup if necessary, ensuring that all malicious artifacts are removed and system integrity is maintained.
* Implement additional monitoring and logging on the affected system and network to detect any recurrence of similar activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if broader organizational impacts exist.


## Rule query [_rule_query_5946]

```js
/* This rule is compatible with Elastic Endpoint only */

process where host.os.type == "windows" and event.action == "start" and

 /* process creation via seclogon */
 process.parent.Ext.real.pid > 0 and

 /* PrivEsc to SYSTEM */
 user.id : "S-1-5-18"  and

 /* Common FPs - evasion via hollowing is possible, should be covered by code injection */
 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\Windows\\System32\\Wermgr.exe",
                           "?:\\Windows\\SysWOW64\\Wermgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe") and
 /* Logon Utilities */
 not (process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
     process.executable : ("?:\\Windows\\System32\\osk.exe",
                           "?:\\Windows\\System32\\Narrator.exe",
                           "?:\\Windows\\System32\\Magnify.exe")) and

 not process.parent.executable : "?:\\Windows\\System32\\AtBroker.exe" and

 not (process.code_signature.subject_name in
           ("philandro Software GmbH", "Freedom Scientific Inc.", "TeamViewer Germany GmbH", "Projector.is, Inc.",
            "TeamViewer GmbH", "Cisco WebEx LLC", "Dell Inc") and process.code_signature.trusted == true) and

 /* AM_Delta_Patch Windows Update */
 not (process.executable : ("?:\\Windows\\System32\\MpSigStub.exe", "?:\\Windows\\SysWOW64\\MpSigStub.exe") and
      process.parent.executable : ("?:\\Windows\\System32\\wuauclt.exe",
                                   "?:\\Windows\\SysWOW64\\wuauclt.exe",
                                   "?:\\Windows\\UUS\\Packages\\Preview\\*\\wuaucltcore.exe",
                                   "?:\\Windows\\UUS\\amd64\\wuauclt.exe",
                                   "?:\\Windows\\UUS\\amd64\\wuaucltcore.exe",
                                   "?:\\ProgramData\\Microsoft\\Windows\\UUS\\*\\wuaucltcore.exe")) and
 not (process.executable : ("?:\\Windows\\System32\\MpSigStub.exe", "?:\\Windows\\SysWOW64\\MpSigStub.exe") and process.parent.executable == null) and

 /* Other third party SW */
 not process.parent.executable :
                   ("?:\\Program Files (x86)\\HEAT Software\\HEAT Remote\\HEATRemoteServer.exe",
                    "?:\\Program Files (x86)\\VisualCron\\VisualCronService.exe",
                    "?:\\Program Files\\BinaryDefense\\Vision\\Agent\\bds-vision-agent-app.exe",
                    "?:\\Program Files\\Tablet\\Wacom\\WacomHost.exe",
                    "?:\\Program Files (x86)\\LogMeIn\\x64\\LogMeIn.exe",
                    "?:\\Program Files (x86)\\EMC Captiva\\Captiva Cloud Runtime\\Emc.Captiva.WebCaptureRunner.exe",
                    "?:\\Program Files\\Freedom Scientific\\*.exe",
                    "?:\\Program Files (x86)\\Google\\Chrome Remote Desktop\\*\\remoting_host.exe",
                    "?:\\Program Files (x86)\\GoToAssist Remote Support Customer\\*\\g2ax_comm_customer.exe") and
 not (
    process.code_signature.trusted == true and process.code_signature.subject_name == "Netwrix Corporation" and
    process.name : "adcrcpy.exe" and process.parent.executable : (
      "?:\\Program Files (x86)\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.EventCollector.exe",
      "?:\\Program Files (x86)\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.Analyzer.exe",
      "?:\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.EventCollector.exe"
    )
 )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Create Process with Token
    * ID: T1134.002
    * Reference URL: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

* Sub-technique:

    * Name: Parent PID Spoofing
    * ID: T1134.004
    * Reference URL: [https://attack.mitre.org/techniques/T1134/004/](https://attack.mitre.org/techniques/T1134/004/)



