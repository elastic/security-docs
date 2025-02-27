---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-outlook-home-page-registry-modification.html
---

# Outlook Home Page Registry Modification [prebuilt-rule-8-17-4-outlook-home-page-registry-modification]

Identifies modifications in registry keys associated with abuse of the Outlook Home Page functionality for command and control or persistence.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
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

* [https://cloud.google.com/blog/topics/threat-intelligence/breaking-the-rules-tough-outlook-for-home-page-attacks/](https://cloud.google.com/blog/topics/threat-intelligence/breaking-the-rules-tough-outlook-for-home-page-attacks/)
* [https://github.com/trustedsec/specula](https://github.com/trustedsec/specula)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Command and Control
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 202

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4691]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Outlook Home Page Registry Modification**

The Outlook Home Page feature allows users to set a webpage as the default view for folders, leveraging registry keys to store URL configurations. Adversaries exploit this by modifying these keys to redirect to malicious sites, enabling command and control or persistence. The detection rule identifies suspicious registry changes, focusing on URL entries within specific paths, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the registry path and value to confirm the presence of a suspicious URL entry in the specified registry paths, such as "HKCU\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL".
* Investigate the URL found in the registry data strings to determine if it is known to be malicious or associated with suspicious activity.
* Check the modification history of the registry key to identify when the change occurred and which user or process made the modification.
* Correlate the registry modification event with other security events on the host, such as network connections or process executions, to identify potential malicious activity.
* Assess the affected system for signs of compromise, including unusual network traffic or unauthorized access attempts, to determine the scope of the incident.
* Consult threat intelligence sources to see if the URL or related indicators are associated with known threat actors or campaigns.

**False positive analysis**

* Legitimate software updates or installations may modify the registry keys associated with Outlook’s Home Page feature. Users can create exceptions for known software update processes to prevent unnecessary alerts.
* Custom scripts or administrative tools used by IT departments to configure Outlook settings across multiple machines might trigger this rule. Identifying and excluding these trusted scripts or tools can reduce false positives.
* Some third-party Outlook add-ins or plugins may alter the registry keys for legitimate purposes. Users should verify the legitimacy of these add-ins and whitelist them if they are deemed safe.
* Automated backup or recovery solutions that restore Outlook settings might cause registry changes. Users can exclude these processes if they are part of a regular and secure backup routine.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further communication with potentially malicious sites.
* Use endpoint detection and response (EDR) tools to terminate any suspicious processes associated with the modified registry keys.
* Restore the modified registry keys to their default values to remove the malicious URL configuration.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional threats.
* Review and analyze network logs to identify any outbound connections to suspicious domains or IP addresses, and block these at the firewall.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if other systems are affected.
* Implement additional monitoring on the affected system and similar endpoints to detect any recurrence of the threat, focusing on registry changes and network activity.


## Rule query [_rule_query_5646]

```js
registry where host.os.type == "windows" and event.action != "deletion" and registry.value : "URL" and
    registry.path : (
        "HKCU\\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL",
        "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL",
        "HKU\\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL",
        "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL",
        "USER\\*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\Inbox\\URL"
    ) and registry.data.strings : "*http*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)

* Sub-technique:

    * Name: Outlook Home Page
    * ID: T1137.004
    * Reference URL: [https://attack.mitre.org/techniques/T1137/004/](https://attack.mitre.org/techniques/T1137/004/)



