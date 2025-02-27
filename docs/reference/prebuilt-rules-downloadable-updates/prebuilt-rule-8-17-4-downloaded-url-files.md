---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-downloaded-url-files.html
---

# Downloaded URL Files [prebuilt-rule-8-17-4-downloaded-url-files]

Identifies .url shortcut files downloaded from outside the local network. These shortcut files are commonly used in phishing campaigns.

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

## Investigation guide [_investigation_guide_4840]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Downloaded URL Files**

URL shortcut files, typically used for quick access to web resources, can be exploited by attackers in phishing schemes to execute malicious content. These files, when downloaded from non-local sources, may bypass traditional security measures. The detection rule identifies such files by monitoring their creation events on Windows systems, focusing on those not initiated by standard processes like Explorer, and flags them based on their network origin, aiding in early threat detection.

**Possible investigation steps**

* Review the file creation event details to confirm the file extension is ".url" and verify the zone identifier is greater than 1, indicating a non-local source.
* Investigate the process that created the .url file, ensuring it was not initiated by "explorer.exe" and identify the actual process responsible for the creation.
* Check the network origin of the downloaded .url file to determine if it is from a known malicious domain or IP address.
* Analyze the contents of the .url file to identify the target URL and assess its reputation and potential risk.
* Correlate the event with other security alerts or logs from the same host to identify any additional suspicious activities or patterns.
* Contact the user associated with the alert to verify if they intentionally downloaded the file and gather any additional context regarding their actions.

**False positive analysis**

* Corporate applications that generate .url files for legitimate purposes may trigger alerts. Identify these applications and create exceptions for their processes to prevent unnecessary alerts.
* Automated scripts or system management tools that download .url files as part of routine operations can be mistaken for threats. Review these tools and whitelist their activities if they are verified as safe.
* User-initiated downloads from trusted internal web portals might be flagged. Educate users on safe downloading practices and consider excluding specific trusted domains from monitoring.
* Security software updates or patches that include .url files could be misidentified. Verify the source of these updates and adjust the rule to exclude known safe update processes.
* Collaboration platforms that share .url files for internal use may cause false positives. Evaluate the platform’s behavior and exclude its processes if they are deemed secure.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of any potential malicious activity.
* Terminate any suspicious processes that are not initiated by standard processes like Explorer, especially those related to the creation of .url files.
* Delete the identified .url files from the system to remove the immediate threat.
* Conduct a full antivirus and anti-malware scan on the affected system to identify and remove any additional threats.
* Review and analyze the network logs to identify any other systems that may have downloaded similar .url files and apply the same containment measures.
* Escalate the incident to the security operations team for further investigation and to determine if there is a broader campaign targeting the organization.
* Update security policies and endpoint protection configurations to block the download and execution of .url files from untrusted sources in the future.


## Rule query [_rule_query_5795]

```js
file where host.os.type == "windows" and event.type == "creation" and file.extension == "url"
   and file.Ext.windows.zone_identifier > 1 and not process.name : "explorer.exe"
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



