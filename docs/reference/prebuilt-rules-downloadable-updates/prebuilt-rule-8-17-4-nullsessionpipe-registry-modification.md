---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-nullsessionpipe-registry-modification.html
---

# NullSessionPipe Registry Modification [prebuilt-rule-8-17-4-nullsessionpipe-registry-modification]

Identifies NullSessionPipe registry modifications that specify which pipes can be accessed anonymously. This could be indicative of adversary lateral movement preparation by making the added pipe available to everyone.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4883]

**Triage and analysis**

[TBC: QUOTE]
**Investigating NullSessionPipe Registry Modification**

The NullSessionPipe registry setting in Windows defines which named pipes can be accessed without authentication, facilitating anonymous connections. Adversaries may exploit this by modifying the registry to enable lateral movement, allowing unauthorized access to network resources. The detection rule monitors changes to this registry path, flagging modifications that introduce new accessible pipes, which could indicate malicious intent.

**Possible investigation steps**

* Review the registry event details to confirm the specific named pipes added or modified in the NullSessionPipes registry path. Focus on the registry.data.strings field to identify any new or suspicious entries.
* Correlate the timestamp of the registry change event with other security events or logs from the same host to identify any concurrent suspicious activities, such as unusual network connections or process executions.
* Investigate the user account or process responsible for the registry modification by examining the event data for user context or process identifiers. This can help determine if the change was made by an unauthorized user or malicious process.
* Check for any recent alerts or logs related to lateral movement or unauthorized access attempts on the network, focusing on the host where the registry change was detected.
* Assess the risk and impact of the modified named pipes by determining if they are commonly used in legitimate operations or if they are known to be exploited by malware or threat actors.

**False positive analysis**

* Legitimate administrative tools or scripts may modify the NullSessionPipe registry setting as part of routine network management. Review the source of the change and verify if it aligns with known administrative activities.
* Some network services or applications might require anonymous access to specific pipes for functionality. Identify these services and document them to differentiate between expected and unexpected modifications.
* Scheduled tasks or automated deployment scripts could alter the registry setting during updates or installations. Ensure these tasks are documented and verify their legitimacy.
* Security software or network monitoring tools might adjust the NullSessionPipe settings for scanning purposes. Confirm with your security team if such tools are in use and adjust the detection rule to exclude these known activities.
* Regularly review and update the list of known exceptions in your detection system to prevent alert fatigue and ensure focus on genuine threats.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Review the registry changes to identify any unauthorized pipes added to the NullSessionPipes registry key and remove them to restore secure configurations.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to detect and remove any malicious software that may have been introduced.
* Analyze network logs and system event logs to identify any unauthorized access attempts or successful connections made through the modified pipes, and block any suspicious IP addresses or accounts.
* Reset credentials for any accounts that may have been compromised or used in conjunction with the unauthorized access to ensure they cannot be reused by adversaries.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been affected.
* Implement enhanced monitoring and alerting for changes to the NullSessionPipes registry key and similar registry paths to detect and respond to future unauthorized modifications promptly.


## Rule query [_rule_query_5838]

```js
registry where host.os.type == "windows" and event.type == "change" and
registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\services\\LanmanServer\\Parameters\\NullSessionPipes",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\services\\LanmanServer\\Parameters\\NullSessionPipes",
    "MACHINE\\SYSTEM\\*ControlSet*\\services\\LanmanServer\\Parameters\\NullSessionPipes"
) and length(registry.data.strings) > 0 and
not registry.data.strings : "(empty)"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



