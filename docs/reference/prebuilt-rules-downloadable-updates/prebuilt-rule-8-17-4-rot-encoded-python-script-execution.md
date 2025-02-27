---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-rot-encoded-python-script-execution.html
---

# ROT Encoded Python Script Execution [prebuilt-rule-8-17-4-rot-encoded-python-script-execution]

Identifies the execution of a Python script that uses the ROT cipher for letters substitution. Adversaries may use this method to encode and obfuscate part of their malicious code in legit python packages.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.file-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/dprk-code-of-conduct](https://www.elastic.co/security-labs/dprk-code-of-conduct)
* [https://www.reversinglabs.com/blog/fake-recruiter-coding-tests-target-devs-with-malicious-python-packages](https://www.reversinglabs.com/blog/fake-recruiter-coding-tests-target-devs-with-malicious-python-packages)

**Tags**:

* Domain: Endpoint
* OS: Windows
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3960]

**Triage and analysis**

[TBC: QUOTE]
**Investigating ROT Encoded Python Script Execution**

ROT encoding, a simple letter substitution cipher, is often used to obfuscate Python scripts, making them harder to analyze. Adversaries exploit this by embedding ROT-encoded scripts within legitimate packages to evade detection. The detection rule identifies such activities by monitoring Python script executions and the presence of ROT-encoded compiled files, flagging potential misuse on Windows and macOS systems.

**Possible investigation steps**

* Review the process entity ID to identify the specific Python process that triggered the alert and gather details such as the process start time and command line arguments.
* Examine the file path and name of the ROT-encoded compiled file (e.g., "rot_??.cpython-*.pyc") to determine its origin and whether it is part of a legitimate package or potentially malicious.
* Check the parent process of the Python script to understand how it was initiated and whether it was executed by a legitimate application or user.
* Investigate the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Analyze any network connections or file modifications made by the Python process to identify potential data exfiltration or further malicious activity.
* Correlate this alert with other security events or logs from the same host to identify patterns or additional indicators of compromise.

**False positive analysis**

* Legitimate development activities may trigger the rule if developers use ROT encoding for testing or educational purposes. To manage this, create exceptions for known development environments or specific user accounts involved in such activities.
* Automated scripts or tools that use ROT encoding for legitimate data processing tasks can be flagged. Identify these scripts and whitelist their execution paths or associated process names to prevent false alerts.
* Some security tools or software may use ROT encoding as part of their normal operations. Review and document these tools, then configure the detection system to exclude their known file paths or process identifiers.
* Regularly scheduled tasks or cron jobs that involve ROT-encoded files for non-malicious purposes can cause false positives. Exclude these tasks by specifying their unique identifiers or execution schedules in the detection rule settings.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potentially malicious activity.
* Terminate any running Python processes that are identified as executing ROT-encoded scripts to halt the execution of obfuscated code.
* Conduct a thorough review of the affected system to identify and remove any ROT-encoded Python files, specifically targeting files matching the pattern "rot_??.cpython-**.pyc**".
* Restore any affected systems from a known good backup to ensure the removal of any persistent threats.
* Implement application whitelisting to prevent unauthorized Python scripts from executing, focusing on blocking scripts with ROT encoding patterns.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Update detection mechanisms to monitor for similar ROT-encoded script activities, enhancing the ability to detect and respond to future threats.


## Rule query [_rule_query_4977]

```js
sequence by process.entity_id with maxspan=1m
 [process where host.os.type in ("windows", "macos") and event.type == "start" and process.name : "python*"]
 [file where host.os.type in ("windows", "macos") and
  event.action != "deletion" and process.name : "python*" and file.name : "rot_??.cpython-*.pyc*"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Sub-technique:

    * Name: Encrypted/Encoded File
    * ID: T1027.013
    * Reference URL: [https://attack.mitre.org/techniques/T1027/013/](https://attack.mitre.org/techniques/T1027/013/)



