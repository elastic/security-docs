---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/script-execution-via-microsoft-html-application.html
---

# Script Execution via Microsoft HTML Application [script-execution-via-microsoft-html-application]

Identifies the execution of scripts via HTML applications using Windows utilities rundll32.exe or mshta.exe. Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-system.security*
* logs-windows.sysmon_operational-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: System
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 202

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_908]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Script Execution via Microsoft HTML Application**

Microsoft HTML Applications (HTA) allow scripts to run in a trusted environment, often using utilities like `rundll32.exe` or `mshta.exe`. Adversaries exploit this by executing malicious scripts under the guise of legitimate processes, bypassing defenses. The detection rule identifies suspicious script execution patterns, such as unusual command lines or execution from common download locations, to flag potential abuse.

**Possible investigation steps**

* Review the process command line details to identify any suspicious patterns or indicators of malicious activity, such as the presence of script execution commands like "eval", "GetObject", or "WScript.Shell".
* Check the parent process executable path to determine if the process was spawned by a known legitimate application or if it deviates from expected behavior, especially if it is not from the specified exceptions like Citrix, Microsoft Office, or Quokka.Works GTInstaller.
* Investigate the origin of the HTA file, particularly if it was executed from common download locations like the Downloads folder or temporary archive extraction paths, to assess if it was downloaded from the internet or extracted from an archive.
* Analyze the process arguments and count to identify any unusual or unexpected parameters that could indicate malicious intent, especially if the process name is "mshta.exe" and the command line does not include typical HTA or HTM file references.
* Correlate the event with other security logs and alerts from data sources like Sysmon, SentinelOne, or Microsoft Defender for Endpoint to gather additional context and determine if this activity is part of a broader attack pattern.

**False positive analysis**

* Execution of legitimate scripts by enterprise applications like Citrix, Microsoft Office, or Quokka.Works GTInstaller can trigger false positives. Users can mitigate this by adding these applications to the exclusion list in the detection rule.
* Scripts executed by mshta.exe that do not involve malicious intent, such as internal web applications or administrative scripts, may be flagged. Users should review these scripts and, if deemed safe, exclude them based on specific command line patterns or parent processes.
* HTA files downloaded from trusted internal sources or vendors might be mistakenly identified as threats. Users can create exceptions for these sources by specifying trusted download paths or file hashes.
* Temporary files created by legitimate software installations or updates in user temp directories can be misinterpreted as malicious. Users should monitor these activities and exclude known safe processes or directories from the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of the malicious script or unauthorized access.
* Terminate any suspicious processes identified by the detection rule, specifically those involving `rundll32.exe` or `mshta.exe` with unusual command lines.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious files or scripts.
* Review and analyze the command lines and scripts executed to understand the scope and intent of the attack, and identify any additional compromised systems.
* Restore the affected system from a known good backup if malicious activity is confirmed and cannot be fully remediated.
* Implement network segmentation to limit the ability of similar threats to propagate across the network in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data have been compromised.


## Rule query [_rule_query_964]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("rundll32.exe", "mshta.exe") and
  (
     (process.command_line :
        (
        "*script*eval(*",
         "*script*GetObject*",
         "*.regread(*",
         "*WScript.Shell*",
         "*.run(*",
         "*).Exec()*",
         "*mshta*http*",
         "*mshtml*RunHTMLApplication*",
         "*mshtml*,#135*",
         "*StrReverse*",
         "*.RegWrite*",
         /* Issue #379 */
         "*window.close(*",
         "* Chr(*"
         )
     and not process.parent.executable :
                  ("?:\\Program Files (x86)\\Citrix\\System32\\wfshell.exe",
                   "?:\\Program Files (x86)\\Microsoft Office\\Office*\\MSACCESS.EXE",
                   "?:\\Program Files\\Quokka.Works GTInstaller\\GTInstaller.exe")
     ) or

    (process.name : "mshta.exe" and
     not process.command_line : ("*.hta*", "*.htm*", "-Embedding") and process.args_count >=2) or

     /* Execution of HTA file downloaded from the internet */
     (process.name : "mshta.exe" and process.command_line : "*\\Users\\*\\Downloads\\*.hta*") or

     /* Execution of HTA file from archive */
     (process.name : "mshta.exe" and
      process.args : ("?:\\Users\\*\\Temp\\7z*", "?:\\Users\\*\\Temp\\Rar$*", "?:\\Users\\*\\Temp\\Temp?_*", "?:\\Users\\*\\Temp\\BNZ.*"))
   )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)



