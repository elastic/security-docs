---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-local-account-tokenfilter-policy-disabled.html
---

# Local Account TokenFilter Policy Disabled [prebuilt-rule-8-17-4-local-account-tokenfilter-policy-disabled]

Identifies registry modification to the LocalAccountTokenFilterPolicy policy. If this value exists (which doesn’t by default) and is set to 1, then remote connections from all local members of Administrators are granted full high-integrity tokens during negotiation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439](https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439)
* [https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167](https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167)
* [https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf](https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4786]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Local Account TokenFilter Policy Disabled**

The LocalAccountTokenFilterPolicy is a Windows registry setting that, when enabled, allows remote connections from local administrators to use full high-integrity tokens. Adversaries may exploit this to bypass User Account Control (UAC) and gain elevated privileges remotely. The detection rule monitors changes to this registry setting, identifying potential unauthorized modifications that could indicate an attempt to facilitate lateral movement or evade defenses.

**Possible investigation steps**

* Review the registry event logs to confirm the change to the LocalAccountTokenFilterPolicy setting, specifically looking for entries where the registry.value is "LocalAccountTokenFilterPolicy" and registry.data.strings is "1" or "0x00000001".
* Identify the user account and process responsible for the registry modification by examining the associated event logs for user and process information.
* Check for any recent remote connections to the affected system, focusing on connections initiated by local administrator accounts, to determine if the change was exploited for lateral movement.
* Investigate any other recent registry changes on the host to identify potential patterns of unauthorized modifications that could indicate broader malicious activity.
* Correlate the event with other security alerts or logs from data sources like Elastic Endgame, Elastic Defend, Sysmon, SentinelOne, or Microsoft Defender for Endpoint to gather additional context and assess the scope of the potential threat.
* Assess the system for signs of compromise or malicious activity, such as unusual processes, network connections, or file modifications, that may have occurred around the time of the registry change.

**False positive analysis**

* Administrative tools or scripts that modify the LocalAccountTokenFilterPolicy for legitimate configuration purposes may trigger alerts. To manage this, identify and document these tools, then create exceptions for their known registry changes.
* System updates or patches that adjust registry settings as part of their installation process can cause false positives. Monitor update schedules and correlate alerts with these activities to determine if they are benign.
* Security software or management solutions that enforce policy changes across endpoints might modify this registry setting. Verify these actions with your IT or security team and consider excluding these processes from triggering alerts.
* Custom scripts or automation tasks used for system hardening or configuration management may alter this setting. Review these scripts and whitelist their expected changes to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Revert the registry setting for LocalAccountTokenFilterPolicy to its default state if it was modified without authorization.
* Conduct a thorough review of recent administrative activities and access logs on the affected system to identify any unauthorized access or changes.
* Reset passwords for all local administrator accounts on the affected system to prevent potential misuse of compromised credentials.
* Deploy endpoint detection and response (EDR) tools to monitor for any further suspicious activities or attempts to modify registry settings.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement additional network segmentation and access controls to limit administrative access to critical systems and reduce the risk of similar threats.


## Rule query [_rule_query_5741]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "LocalAccountTokenFilterPolicy" and
  registry.path : (
    "HKLM\\*\\LocalAccountTokenFilterPolicy",
    "\\REGISTRY\\MACHINE\\*\\LocalAccountTokenFilterPolicy",
    "MACHINE\\*\\LocalAccountTokenFilterPolicy"
  ) and registry.data.strings : ("1", "0x00000001")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Pass the Hash
    * ID: T1550.002
    * Reference URL: [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)



