---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-remote-file-execution-via-msiexec.html
---

# Potential Remote File Execution via MSIEXEC [prebuilt-rule-8-17-4-potential-remote-file-execution-via-msiexec]

Identifies the execution of the built-in Windows Installer, msiexec.exe, to install a remote package. Adversaries may abuse msiexec.exe to launch local or network accessible MSI files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4866]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Remote File Execution via MSIEXEC**

MSIEXEC, the Windows Installer, facilitates software installation, modification, and removal. Adversaries exploit it to execute remote MSI files, bypassing security controls. The detection rule identifies suspicious MSIEXEC activity by monitoring process starts, network connections, and child processes, filtering out known benign signatures and paths, thus highlighting potential misuse for initial access or defense evasion.

**Possible investigation steps**

* Review the process start event for msiexec.exe to identify the command-line arguments used, focusing on the presence of the "/V" flag, which indicates a remote installation attempt.
* Examine the network connection attempts associated with msiexec.exe to determine the remote IP addresses or domains being contacted, and assess their reputation or any known associations with malicious activity.
* Investigate the child processes spawned by msiexec.exe, especially those not matching known benign executables or paths, to identify any suspicious or unexpected activity.
* Check the user ID associated with the msiexec.exe process to verify if it aligns with expected user behavior or if it indicates potential compromise, especially focusing on user IDs like "S-1-5-21-**" or "S-1-5-12-1-**".
* Analyze the code signature of any child processes to ensure they are trusted and expected, paying particular attention to any unsigned or untrusted executables.
* Correlate the alert with any recent phishing attempts or suspicious emails received by the user, as the MITRE ATT&CK technique T1566 (Phishing) is associated with this rule.

**False positive analysis**

* Legitimate software installations using msiexec.exe may trigger the rule. To manage this, create exceptions for known software update processes that use msiexec.exe with trusted code signatures.
* System maintenance tasks that involve msiexec.exe, such as Windows updates or system repairs, can be excluded by identifying and allowing specific system paths and executables involved in these processes.
* Enterprise software deployment tools that utilize msiexec.exe for remote installations might cause false positives. Exclude these by verifying the code signature and adding exceptions for trusted deployment tools.
* Administrative scripts or automation tools that invoke msiexec.exe for legitimate purposes should be reviewed and, if verified as safe, excluded based on their execution context and code signature.
* Network monitoring tools or security software that simulate msiexec.exe activity for testing or monitoring purposes can be excluded by identifying their specific signatures and paths.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration. This can be done by disabling network interfaces or moving the system to a quarantine VLAN.
* Terminate the msiexec.exe process if it is still running to stop any ongoing malicious activity. Use task management tools or scripts to ensure the process is completely stopped.
* Conduct a thorough review of the system for any unauthorized changes or installations. Check for newly installed software or modifications to system files that could indicate further compromise.
* Restore the system from a known good backup if unauthorized changes are detected and cannot be easily reversed. Ensure the backup is clean and free from any malicious alterations.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited. This includes applying all relevant Windows updates and security patches.
* Enhance monitoring and logging on the affected system and network to detect any similar future attempts. Ensure that all relevant security events are being captured and analyzed.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected. Provide them with all relevant logs and findings for a comprehensive analysis.


## Rule query [_rule_query_5821]

```js
sequence with maxspan=1m
 [process where host.os.type == "windows" and event.action == "start" and
    process.name : "msiexec.exe" and process.args : "/V"] by process.entity_id
 [network where host.os.type == "windows" and process.name : "msiexec.exe" and
    event.action == "connection_attempted"] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : "msiexec.exe" and user.id : ("S-1-5-21-*", "S-1-5-12-1-*") and
  not process.executable : ("?:\\Windows\\SysWOW64\\msiexec.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\srtasks.exe",
                            "?:\\Windows\\SysWOW64\\srtasks.exe",
                            "?:\\Windows\\System32\\taskkill.exe",
                            "?:\\Windows\\Installer\\MSI*.tmp",
                            "?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\ie4uinit.exe",
                            "?:\\Windows\\SysWOW64\\ie4uinit.exe",
                            "?:\\Windows\\System32\\sc.exe",
                            "?:\\Windows\\system32\\Wbem\\mofcomp.exe",
                            "?:\\Windows\\twain_32\\fjscan32\\SOP\\crtdmprc.exe",
                            "?:\\Windows\\SysWOW64\\taskkill.exe",
                            "?:\\Windows\\SysWOW64\\schtasks.exe",
                            "?:\\Windows\\system32\\schtasks.exe",
                            "?:\\Windows\\System32\\sdbinst.exe") and
  not (process.code_signature.subject_name == "Citrix Systems, Inc." and process.code_signature.trusted == true) and
  not (process.name : ("regsvr32.exe", "powershell.exe", "rundll32.exe", "wscript.exe") and
       process.Ext.token.integrity_level_name == "high" and
       process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")) and
  not (process.executable : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and process.code_signature.trusted == true) and
  not (process.name : "rundll32.exe" and process.args : "printui.dll,PrintUIEntry")
  ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



