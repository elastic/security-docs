---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-microsoft-build-engine-started-by-an-office-application.html
---

# Microsoft Build Engine Started by an Office Application [prebuilt-rule-8-4-2-microsoft-build-engine-started-by-an-office-application]

An instance of MSBuild, the Microsoft Build Engine, was started by Excel or Word. This is unusual behavior for the Build Engine and could have been caused by an Excel or Word document executing a malicious script payload.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html](https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3405]

## Triage and analysis

## Investigating Microsoft Build Engine Started by an Office Application

Microsoft Office (MS Office) is a suite of applications designed to help with productivity and completing common tasks on a computer. You can create and edit documents containing text and images, work with data in spreadsheets and databases, and create presentations and posters. As it is some of the most-used software across companies, MS Office is frequently targeted for initial access. It also has a wide variety of capabilities that attackers can take advantage of.

The Microsoft Build Engine is a platform for building applications. This engine, also known as MSBuild, provides an XML schema for a project file that controls how the build platform processes and builds software, and can be abused to proxy execution of code.

This rule looks for the `Msbuild.exe` utility spawned by MS Office programs. This is generally the result of the execution of malicious documents.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Retrieve MS Office documents received and opened by the user that could cause this behavior. Common locations include, but are not limited to, the Downloads and Document folders and the folder configured at the email client.
- Determine if the collected files are malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
  - If the malicious file was delivered via phishing:
    - Block the email sender from sending future emails.
    - Block the malicious web pages.
    - Remove emails from the sender from mailboxes.
    - Consider improvements to the security awareness program.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4047]

```js
process where event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("eqnedt32.exe",
                         "excel.exe",
                         "fltldr.exe",
                         "msaccess.exe",
                         "mspub.exe",
                         "outlook.exe",
                         "powerpnt.exe",
                         "winword.exe" )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



