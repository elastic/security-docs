---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-office-test-registry-persistence.html
---

# Office Test Registry Persistence [prebuilt-rule-8-17-4-office-test-registry-persistence]

Identifies the modification of the Microsoft Office "Office Test" Registry key, a registry location that can be used to specify a DLL which will be executed every time an MS Office application is started. Attackers can abuse this to gain persistence on a compromised host.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* logs-m365_defender.event-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/](https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4918]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Office Test Registry Persistence**

The Office Test Registry key in Windows environments allows specifying a DLL to execute whenever an Office application starts, providing a mechanism for legitimate customization. However, adversaries can exploit this for persistence by loading malicious DLLs. The detection rule monitors modifications to this registry path, excluding deletions, to identify potential abuse, leveraging data from various security sources to flag suspicious activity.

**Possible investigation steps**

* Review the registry event details to identify the specific DLL path that was added or modified in the Office Test Registry key.
* Check the file properties and digital signature of the DLL specified in the registry modification to determine its legitimacy.
* Investigate the source of the registry modification by correlating with user activity logs to identify which user account made the change.
* Analyze recent process execution logs for any Office applications to detect if the suspicious DLL has been loaded or executed.
* Cross-reference the DLL and associated registry modification with threat intelligence sources to check for known malicious indicators.
* Examine the system for additional signs of compromise, such as unusual network connections or other persistence mechanisms, to assess the scope of potential intrusion.

**False positive analysis**

* Legitimate software installations or updates may modify the Office Test Registry key as part of their setup process. Users can create exceptions for known software vendors or specific applications that are frequently updated.
* System administrators might use scripts or management tools that modify the registry for configuration purposes. Identify and exclude these trusted scripts or tools from triggering alerts.
* Customization by IT departments for legitimate business needs can lead to registry modifications. Document and whitelist these customizations to prevent false positives.
* Security software or monitoring tools might interact with the registry as part of their normal operations. Verify and exclude these interactions if they are known to be safe and necessary for system functionality.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further spread or communication with potential command and control servers.
* Use endpoint detection and response (EDR) tools to terminate any suspicious processes associated with the malicious DLL identified in the registry path.
* Remove the malicious DLL entry from the Office Test Registry key to prevent it from executing on future Office application startups.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious files or remnants.
* Review recent user activity and system logs to identify any unauthorized access or changes that may have led to the registry modification, and reset credentials if necessary.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar registry modifications across the network to detect and respond to future attempts promptly.


## Rule query [_rule_query_5873]

```js
registry where host.os.type == "windows" and event.action != "deletion" and
    registry.path : "*\\Software\\Microsoft\\Office Test\\Special\\Perf\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)

* Sub-technique:

    * Name: Office Test
    * ID: T1137.002
    * Reference URL: [https://attack.mitre.org/techniques/T1137/002/](https://attack.mitre.org/techniques/T1137/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



