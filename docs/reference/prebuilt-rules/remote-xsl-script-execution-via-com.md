---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/remote-xsl-script-execution-via-com.html
---

# Remote XSL Script Execution via COM [remote-xsl-script-execution-via-com]

Identifies the execution of a hosted XSL script using the Microsoft.XMLDOM COM interface via Microsoft Office processes. This behavior may indicate adversarial activity to execute malicious JScript or VBScript on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.library-*

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

## Investigation guide [_investigation_guide_879]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Remote XSL Script Execution via COM**

The Microsoft.XMLDOM COM interface allows applications to parse and transform XML documents using XSL scripts. Adversaries exploit this by embedding malicious scripts in Office documents, triggering execution via Office processes like Word or Excel. The detection rule identifies suspicious activity by monitoring for the loading of specific DLLs and the execution of unexpected child processes, indicating potential script execution attempts.

**Possible investigation steps**

* Review the alert details to identify the specific Office process (e.g., winword.exe, excel.exe) that triggered the alert and note the process entity ID for further investigation.
* Check the process tree to identify any unexpected child processes spawned by the Office application, focusing on those not matching typical system executables like WerFault.exe or conhost.exe.
* Investigate the loaded DLLs, specifically msxml3.dll, to confirm its legitimate use and check for any anomalies or unusual patterns in its loading sequence.
* Analyze the parent and child process relationships to determine if the execution flow aligns with typical user activity or if it suggests malicious behavior.
* Gather additional context by reviewing recent user activity and document interactions to identify any potential phishing attempts or suspicious document handling that could have led to the alert.
* Correlate the findings with other security events or alerts in the environment to assess if this activity is part of a broader attack pattern or isolated incident.

**False positive analysis**

* Legitimate use of Microsoft Office applications for XML processing can trigger the rule. Users should identify and whitelist known applications or scripts that regularly perform XML transformations using the Microsoft.XMLDOM COM interface.
* Automated document processing systems that utilize Office applications to handle XML data might cause false positives. Exclude these systems by specifying their process names or executable paths in the detection rule.
* Software updates or installations that involve Office applications may load the msxml3.dll and start child processes. Temporarily disable the rule during scheduled maintenance or update windows to prevent false alerts.
* Custom Office add-ins or macros that interact with XML files could be misidentified as threats. Review and approve these add-ins, then adjust the rule to exclude their specific behaviors.
* Regular business processes that involve document conversion or data extraction using Office tools might be flagged. Document these processes and create exceptions based on their unique characteristics, such as specific file paths or process names.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of the malicious script execution.
* Terminate any suspicious processes identified as child processes of Office applications, such as winword.exe or excel.exe, that are not part of the standard executable paths.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious scripts or files.
* Review and restore any altered or deleted files from secure backups to ensure data integrity and system functionality.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement application whitelisting to restrict the execution of unauthorized scripts and executables, particularly those not located in standard directories.
* Enhance monitoring and alerting for similar activities by ensuring that the detection rule is actively deployed and that alerts are configured to notify the appropriate personnel promptly.


## Rule query [_rule_query_935]

```js
sequence with maxspan=1m
 [library where host.os.type == "windows" and dll.name : "msxml3.dll" and
  process.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe")] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe") and
  not process.executable :
        ("?:\\Windows\\System32\\WerFault.exe",
         "?:\\Windows\\SysWoW64\\WerFault.exe",
         "?:\\windows\\splwow64.exe",
         "?:\\Windows\\System32\\conhost.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*exe")] by process.parent.entity_id
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

    * Name: XSL Script Processing
    * ID: T1220
    * Reference URL: [https://attack.mitre.org/techniques/T1220/](https://attack.mitre.org/techniques/T1220/)



