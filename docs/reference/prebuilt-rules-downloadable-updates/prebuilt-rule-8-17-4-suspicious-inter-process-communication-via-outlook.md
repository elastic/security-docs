---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-inter-process-communication-via-outlook.html
---

# Suspicious Inter-Process Communication via Outlook [prebuilt-rule-8-17-4-suspicious-inter-process-communication-via-outlook]

Detects Inter-Process Communication with Outlook via Component Object Model from an unusual process. Adversaries may target user email to collect sensitive information or send email on their behalf via API.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4684]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Inter-Process Communication via Outlook**

Outlook’s integration with the Component Object Model (COM) allows processes to automate tasks like sending emails. Adversaries exploit this by using unusual processes to interact with Outlook, potentially to exfiltrate data or send unauthorized emails. The detection rule identifies such anomalies by monitoring for unexpected processes initiating communication with Outlook, especially those lacking trusted signatures or recently modified, indicating potential malicious activity.

**Possible investigation steps**

* Review the process entity ID to identify the specific process that initiated communication with Outlook and determine if it is one of the unusual processes listed, such as rundll32.exe, mshta.exe, or powershell.exe.
* Check the code signature status of the initiating process. If the process is unsigned or has an untrusted signature, investigate the source and legitimacy of the executable.
* Analyze the relative file creation and modification times of the initiating process. If the process was created or modified recently (within 500 seconds), it may indicate a newly introduced or altered executable, warranting further scrutiny.
* Investigate the effective parent process of OUTLOOK.EXE to understand the context of how Outlook was launched. Determine if the parent process is expected or if it is an unusual or suspicious process.
* Correlate the alert with any recent user activity or changes on the host to identify potential user actions or system changes that could explain the process behavior.
* Examine any network activity associated with the initiating process to identify potential data exfiltration or unauthorized email sending attempts.
* Review any additional alerts or logs related to the host or user account to identify patterns or additional indicators of compromise.

**False positive analysis**

* Legitimate administrative scripts or tools may trigger the rule if they use processes like PowerShell or cmd.exe to automate tasks involving Outlook. To manage this, identify and whitelist these scripts or tools by their specific file paths or hashes.
* Software updates or installations might cause processes to appear as recently modified, leading to false positives. Regularly update the list of trusted software and exclude these known update processes from triggering alerts.
* Custom in-house applications that interact with Outlook for business purposes may be flagged. Ensure these applications are signed with a trusted certificate or add them to an exception list based on their unique identifiers.
* Security tools or monitoring software that perform regular checks on Outlook might be misidentified. Verify these tools and exclude them by their process names or signatures to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified in the alert, particularly those interacting with Outlook, such as rundll32.exe, mshta.exe, or powershell.exe.
* Conduct a thorough review of the email account associated with the affected Outlook process to identify any unauthorized access or email activity. Reset the account credentials if necessary.
* Analyze the process code signatures and file modification times to determine if any legitimate applications have been compromised. Reinstall or update these applications as needed.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar endpoints to detect any recurrence of the suspicious activity.
* Review and update endpoint protection policies to ensure that similar threats are detected and blocked in the future, leveraging the MITRE ATT&CK framework for guidance on email collection techniques.


## Rule query [_rule_query_5639]

```js
sequence with maxspan=1m
[process where host.os.type == "windows" and event.action == "start" and
  (
    process.name : (
      "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
      "cmd.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"
    ) or
    (
      (process.code_signature.trusted == false or process.code_signature.exists == false) and
      (process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)
    )
  )
] by process.entity_id
[process where host.os.type == "windows" and event.action == "start" and process.name : "OUTLOOK.EXE" and
  process.Ext.effective_parent.name != null] by process.Ext.effective_parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Local Email Collection
    * ID: T1114.001
    * Reference URL: [https://attack.mitre.org/techniques/T1114/001/](https://attack.mitre.org/techniques/T1114/001/)

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



