---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-uac-bypass-attempt-via-elevated-com-internet-explorer-add-on-installer.html
---

# UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer [prebuilt-rule-8-17-4-uac-bypass-attempt-via-elevated-com-internet-explorer-add-on-installer]

Identifies User Account Control (UAC) bypass attempts by abusing an elevated COM Interface to launch a malicious program. Attackers may attempt to bypass UAC to stealthily execute code with elevated permissions.

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

* [https://swapcontext.blogspot.com/2020/11/uac-bypasses-from-comautoapprovallist.html](https://swapcontext.blogspot.com/2020/11/uac-bypasses-from-comautoapprovallist.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4980]

**Triage and analysis**

[TBC: QUOTE]
**Investigating UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer**

User Account Control (UAC) is a security feature in Windows designed to prevent unauthorized changes by prompting for elevated permissions. Adversaries may exploit elevated COM interfaces, such as the Internet Explorer Add-On Installer, to bypass UAC and execute malicious code with higher privileges. The detection rule identifies suspicious processes originating from temporary directories, launched by the IE installer with specific arguments, indicating potential UAC bypass attempts.

**Possible investigation steps**

* Review the process details to confirm the executable path matches the pattern "C:\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and verify if it is expected or known within the environment.
* Investigate the parent process "ieinstal.exe" to determine if its execution is legitimate, checking for any unusual or unexpected usage patterns.
* Examine the command-line arguments used by the parent process, specifically looking for the "-Embedding" argument, to understand the context of its execution.
* Check the code signature of the suspicious process to determine if it is signed by a trusted entity, and assess the trustworthiness of the signature if present.
* Correlate this event with other security alerts or logs from data sources like Elastic Endgame, Elastic Defend, Sysmon, Microsoft Defender for Endpoint, or SentinelOne to identify any related malicious activity.
* Investigate the user account associated with the process to determine if there are any signs of compromise or unauthorized access attempts.
* Assess the risk and impact of the potential UAC bypass attempt on the system and broader network, and take appropriate containment or remediation actions if necessary.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule if they temporarily use the specified directory structure. Users can monitor the frequency and context of these alerts to determine if they align with known software behaviors.
* Development or testing environments might generate alerts due to the execution of scripts or applications from temporary directories. Users can create exceptions for specific environments or processes that are known to be safe.
* System administrators or IT personnel performing legitimate administrative tasks might inadvertently trigger the rule. Users can exclude specific user accounts or processes from monitoring if they are verified as non-threatening.
* Automated software deployment tools that use temporary directories for installation processes may cause false positives. Users can whitelist these tools by verifying their code signatures and adding them to an exception list.
* Regularly review and update the list of trusted applications and processes to ensure that only verified and necessary exceptions are in place, minimizing the risk of overlooking genuine threats.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified by the detection rule, specifically those originating from temporary directories and launched by "ieinstal.exe" with the "-Embedding" argument.
* Conduct a thorough review of the affected system to identify any additional unauthorized changes or malware installations, focusing on temporary directories and COM interface usage.
* Restore the system to a known good state using backups or system restore points, ensuring that any malicious changes are reversed.
* Update and patch the affected system to the latest security updates to mitigate known vulnerabilities that could be exploited for UAC bypass.
* Implement application whitelisting to prevent unauthorized executables from running, particularly those in temporary directories.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_5935]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.executable : "C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and
 process.parent.name : "ieinstal.exe" and process.parent.args : "-Embedding"

 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Inter-Process Communication
    * ID: T1559
    * Reference URL: [https://attack.mitre.org/techniques/T1559/](https://attack.mitre.org/techniques/T1559/)

* Sub-technique:

    * Name: Component Object Model
    * ID: T1559.001
    * Reference URL: [https://attack.mitre.org/techniques/T1559/001/](https://attack.mitre.org/techniques/T1559/001/)



