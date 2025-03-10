---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-execution-via-microsoft-office-add-ins.html
---

# Suspicious Execution via Microsoft Office Add-Ins [prebuilt-rule-8-17-4-suspicious-execution-via-microsoft-office-add-ins]

Identifies execution of common Microsoft Office applications to launch an Office Add-In from a suspicious path or with an unusual parent process. This may indicate an attempt to get initial access via a malicious phishing MS Office Add-In.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/Octoberfest7/XLL_Phishing](https://github.com/Octoberfest7/XLL_Phishing)
* [https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/](https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4867]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Execution via Microsoft Office Add-Ins**

Microsoft Office Add-Ins enhance productivity by integrating additional features into Office applications. However, adversaries can exploit this by embedding malicious code within add-ins, often delivered through phishing. The detection rule identifies unusual execution patterns, such as Office apps launching add-ins from suspicious paths or with atypical parent processes, signaling potential threats. It filters out known benign activities to minimize false positives, focusing on genuine anomalies indicative of malicious intent.

**Possible investigation steps**

* Review the process name and arguments to confirm if the execution involves a Microsoft Office application launching an add-in from a suspicious path, as indicated by the process.name and process.args fields.
* Check the parent process name to determine if the Office application was launched by an unusual or potentially malicious parent process, such as cmd.exe or powershell.exe, using the process.parent.name field.
* Investigate the file path from which the add-in was executed to assess if it matches any of the suspicious paths listed in the query, such as the Temp or Downloads directories, using the process.args field.
* Examine the host’s recent activity logs to identify any related events or patterns that might indicate a broader attack or compromise, focusing on the host.os.type and event.type fields.
* Correlate the alert with any recent phishing attempts or suspicious emails received by the user to determine if the execution is part of a phishing campaign, leveraging the MITRE ATT&CK tactic and technique information provided.
* Verify if the execution is a false positive by checking against the known benign activities excluded in the query, such as specific VSTOInstaller.exe paths or arguments, to rule out legitimate software installations or updates.

**False positive analysis**

* Logitech software installations can trigger false positives when VSTO files are executed by Logitech’s PlugInInstallerUtility. To mitigate this, exclude processes with paths related to Logitech installations from the detection rule.
* The VSTOInstaller.exe process may be flagged when uninstalling applications. Exclude processes with the /Uninstall argument to prevent these false positives.
* Rundll32.exe executing with specific arguments related to MSI temporary files can be benign. Exclude these specific rundll32.exe executions to avoid false alerts.
* Sidekick.vsto installations from the specified URL can be legitimate. Exclude this specific VSTOInstaller.exe process with the Sidekick.vsto argument to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any ongoing malicious activity.
* Terminate any suspicious processes identified by the detection rule, such as those involving unusual parent processes or originating from suspicious paths.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious add-ins or related malware.
* Review and clean up any unauthorized or suspicious Office add-ins from the affected applications to ensure no malicious code remains.
* Restore the system from a known good backup if the integrity of the system is compromised and cannot be assured through cleaning alone.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring and alerting for similar suspicious activities to enhance detection and response capabilities for future incidents.


## Rule query [_rule_query_5822]

```js
process where

    host.os.type == "windows" and event.type == "start" and

    process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSACCESS.EXE", "VSTOInstaller.exe") and

    process.args regex~ """.+\.(wll|xll|ppa|ppam|xla|xlam|vsto)""" and

    /* Office Add-In from suspicious paths */
    (process.args :
             ("?:\\Users\\*\\Temp\\7z*",
              "?:\\Users\\*\\Temp\\Rar$*",
              "?:\\Users\\*\\Temp\\Temp?_*",
              "?:\\Users\\*\\Temp\\BNZ.*",
              "?:\\Users\\*\\Downloads\\*",
              "?:\\Users\\*\\AppData\\Roaming\\*",
              "?:\\Users\\Public\\*",
              "?:\\ProgramData\\*",
              "?:\\Windows\\Temp\\*",
              "\\Device\\*",
              "http*") or

    process.parent.name : ("explorer.exe", "OpenWith.exe") or

    /* Office Add-In from suspicious parent */
    process.parent.name : ("cmd.exe", "powershell.exe")) and

    /* False Positives */
    not (process.args : "*.vsto" and
         process.parent.executable :
                   ("?:\\Program Files\\Logitech\\LogiOptions\\PlugInInstallerUtility*.exe",
                    "?:\\ProgramData\\Logishrd\\LogiOptions\\Plugins\\VSTO\\*\\VSTOInstaller.exe",
                    "?:\\Program Files\\Logitech\\LogiOptions\\PlugInInstallerUtility.exe",
                    "?:\\Program Files\\LogiOptionsPlus\\PlugInInstallerUtility*.exe",
                    "?:\\ProgramData\\Logishrd\\LogiOptionsPlus\\Plugins\\VSTO\\*\\VSTOInstaller.exe",
                    "?:\\Program Files\\Common Files\\microsoft shared\\VSTO\\*\\VSTOInstaller.exe")) and
    not (process.args : "/Uninstall" and process.name : "VSTOInstaller.exe") and
    not (process.parent.name : "rundll32.exe" and
         process.parent.args : "?:\\WINDOWS\\Installer\\MSI*.tmp,zzzzInvokeManagedCustomActionOutOfProc") and
    not (process.name : "VSTOInstaller.exe" and process.args : "https://dl.getsidekick.com/outlook/vsto/Sidekick.vsto")
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

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)

* Sub-technique:

    * Name: Add-ins
    * ID: T1137.006
    * Reference URL: [https://attack.mitre.org/techniques/T1137/006/](https://attack.mitre.org/techniques/T1137/006/)



