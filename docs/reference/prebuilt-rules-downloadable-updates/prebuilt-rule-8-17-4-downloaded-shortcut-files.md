---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-downloaded-shortcut-files.html
---

# Downloaded Shortcut Files [prebuilt-rule-8-17-4-downloaded-shortcut-files]

Identifies .lnk shortcut file downloaded from outside the local network. These shortcut files are commonly used in phishing campaigns.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

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
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4839]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Downloaded Shortcut Files**

Shortcut files (.lnk) are used in Windows environments to link to executable files or scripts, streamlining user access. Adversaries exploit this by embedding malicious commands in these files, often distributing them via phishing. The detection rule identifies suspicious .lnk files created on Windows systems, especially those downloaded from external sources, indicating potential phishing attempts. This is achieved by monitoring file creation events and zone identifiers, which help trace the file’s origin.

**Possible investigation steps**

* Review the file creation event details to identify the specific .lnk file and its associated metadata, such as the file path and creation timestamp.
* Examine the zone identifier value to confirm that the file was indeed downloaded from an external source, as indicated by a value greater than 1.
* Investigate the source of the download by checking network logs or browser history to identify the URL or IP address from which the .lnk file was downloaded.
* Analyze the contents of the .lnk file to detect any embedded commands or scripts that may indicate malicious intent.
* Check for any related alerts or events on the same host around the time of the .lnk file creation to identify potential follow-up actions or additional threats.
* Assess the user account associated with the file creation event to determine if the account has been compromised or if the user was targeted in a phishing campaign.

**False positive analysis**

* Corporate software deployments may trigger the rule when legitimate .lnk files are distributed across the network. Users can create exceptions for known software distribution servers to prevent these false positives.
* Automated backup or synchronization tools that create .lnk files as part of their normal operation can be mistaken for threats. Identifying and excluding these tools from the rule can reduce unnecessary alerts.
* User-created shortcuts for frequently accessed network resources might be flagged. Monitoring and excluding specific user activities or directories where these shortcuts are commonly created can help manage these false positives.
* Some legitimate applications may download .lnk files as part of their update process. Identifying these applications and adding them to an exception list can prevent false alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat.
* Quarantine the suspicious .lnk file to prevent execution and further analysis.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Review and remove any unauthorized or suspicious user accounts or privileges that may have been created or altered as a result of the phishing attempt.
* Restore the system from a known good backup if any critical system files or configurations have been compromised.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Update security policies and rules to block similar phishing attempts in the future, such as restricting the execution of .lnk files from untrusted sources.


## Rule query [_rule_query_5794]

```js
file where host.os.type == "windows" and event.type == "creation" and file.extension == "lnk" and file.Ext.windows.zone_identifier > 1
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)

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

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)



