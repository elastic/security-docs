---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-escalation-via-vulnerable-msi-repair.html
---

# Potential Escalation via Vulnerable MSI Repair [prebuilt-rule-8-17-4-potential-escalation-via-vulnerable-msi-repair]

Identifies when a browser process navigates to the Microsoft Help page followed by spawning an elevated process. This may indicate a successful exploitation for privilege escalation abusing a vulnerable Windows Installer repair setup.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* endgame-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://sec-consult.com/blog/detail/msi-installer-repair-to-system-a-detailed-journey/](https://sec-consult.com/blog/detail/msi-installer-repair-to-system-a-detailed-journey/)
* [https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-38014](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-38014)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 203

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4964]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Escalation via Vulnerable MSI Repair**

Windows Installer (MSI) is a service used for software installation and maintenance. Adversaries exploit vulnerabilities in MSI repair functions to gain elevated privileges. This detection rule identifies suspicious activity by monitoring browser processes accessing Microsoft Help pages, followed by elevated process creation, indicating potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific browser process that accessed the Microsoft Help page, noting the process name and command line details.
* Check the user domain associated with the process to confirm if it matches "NT AUTHORITY", "AUTORITE NT", or "AUTORIDADE NT", which may indicate a system-level account was used.
* Investigate the parent process of the browser to determine if it was expected or if it shows signs of compromise or unusual behavior.
* Examine the timeline of events to see if an elevated process was spawned shortly after the browser accessed the Microsoft Help page, indicating potential exploitation.
* Correlate the event with other security logs or alerts from data sources like Elastic Endgame, Sysmon, or Microsoft Defender for Endpoint to gather additional context or evidence of malicious activity.
* Assess the risk and impact of the elevated process by identifying its actions and any changes made to the system, such as modifications to critical files or registry keys.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they involve browser-based help documentation. To manage this, identify and whitelist known software update processes that frequently access Microsoft Help pages.
* Automated scripts or administrative tools that use browsers to access Microsoft Help for legitimate purposes can cause false positives. Exclude these scripts or tools by specifying their unique command-line patterns or process names.
* User-initiated troubleshooting or help-seeking behavior that involves accessing Microsoft Help pages might be misinterpreted as suspicious. Educate users on safe browsing practices and consider excluding specific user accounts or domains that are known to frequently engage in such activities.
* Security tools or monitoring solutions that simulate browser activity for testing purposes may inadvertently trigger the rule. Identify these tools and create exceptions based on their process names or command-line arguments to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate any suspicious elevated processes that were spawned following the browser’s navigation to the Microsoft Help page to halt potential privilege escalation activities.
* Conduct a thorough review of the affected system’s event logs and process creation history to identify any unauthorized changes or additional indicators of compromise.
* Apply the latest security patches and updates to the Windows Installer service and any other vulnerable components to mitigate the exploited vulnerability.
* Restore the affected system from a known good backup if unauthorized changes or persistent threats are detected that cannot be easily remediated.
* Monitor the network for any signs of similar exploitation attempts or related suspicious activities, using enhanced detection rules and threat intelligence feeds.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation and recovery efforts.


## Rule query [_rule_query_5919]

```js
process where event.type == "start" and host.os.type == "windows" and
 user.domain : ("NT AUTHORITY", "AUTORITE NT", "AUTORIDADE NT") and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "whale.exe", "browser.exe", "dragon.exe", "vivaldi.exe",
                        "opera.exe", "iexplore", "firefox.exe", "waterfox.exe", "iexplore.exe", "tor.exe", "safari.exe") and
 process.parent.command_line : "*go.microsoft.com*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



