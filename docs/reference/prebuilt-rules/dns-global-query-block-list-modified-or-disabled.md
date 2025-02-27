---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/dns-global-query-block-list-modified-or-disabled.html
---

# DNS Global Query Block List Modified or Disabled [dns-global-query-block-list-modified-or-disabled]

Identifies changes to the DNS Global Query Block List (GQBL), a security feature that prevents the resolution of certain DNS names often exploited in attacks like WPAD spoofing. Attackers with certain privileges, such as DNSAdmins, can modify or disable the GQBL, allowing exploitation of hosts running WPAD with default settings for privilege escalation and lateral movement.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cube0x0.github.io/Pocing-Beyond-DA/](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wpad-spoofing](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wpad-spoofing)
* [https://www.netspi.com/blog/technical-blog/network-penetration-testing/adidns-revisited/](https://www.netspi.com/blog/technical-blog/network-penetration-testing/adidns-revisited/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_259]

**Triage and analysis**

[TBC: QUOTE]
**Investigating DNS Global Query Block List Modified or Disabled**

The DNS Global Query Block List (GQBL) is a security feature in Windows environments that blocks the resolution of specific DNS names, such as WPAD, to prevent attacks like spoofing. Adversaries with elevated privileges can alter or disable the GQBL, enabling them to exploit default settings for privilege escalation. The detection rule monitors registry changes indicating such modifications, flagging potential defense evasion attempts.

**Possible investigation steps**

* Review the registry event logs to confirm the specific changes made to the DNS Global Query Block List, focusing on the registry values "EnableGlobalQueryBlockList" and "GlobalQueryBlockList".
* Identify the user account associated with the registry change event to determine if the account has elevated privileges, such as DNSAdmins, which could indicate potential misuse.
* Check for any recent changes in user permissions or group memberships that might have granted the necessary privileges to modify the GQBL.
* Investigate any other suspicious activities or alerts related to the same user or host around the time of the registry change to identify potential lateral movement or privilege escalation attempts.
* Correlate the event with network traffic logs to detect any unusual DNS queries or attempts to resolve WPAD or other blocked names, which could suggest exploitation attempts.
* Review system and security logs for any signs of unauthorized access or other indicators of compromise on the affected host.

**False positive analysis**

* Legitimate administrative changes to DNS settings by IT staff can trigger the rule. To manage this, create exceptions for known maintenance windows or authorized personnel making these changes.
* Automated scripts or software updates that modify DNS settings might be flagged. Identify and whitelist these processes if they are verified as safe and necessary for system operations.
* Changes made by security tools or network management software that adjust DNS settings for legitimate reasons can be mistaken for threats. Review and exclude these tools from monitoring if they are part of the organization’s approved security infrastructure.
* In environments where WPAD is intentionally used, the absence of "wpad" in the GlobalQueryBlockList might be a normal configuration. Document and exclude these cases if they align with the organization’s network design and security policies.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement.
* Revert any unauthorized changes to the DNS Global Query Block List by restoring the registry settings to their default state, ensuring WPAD and other critical entries are included.
* Conduct a thorough review of user accounts with elevated privileges, such as DNSAdmins, to identify any unauthorized access or privilege escalation. Revoke unnecessary privileges and reset credentials as needed.
* Deploy endpoint detection and response (EDR) tools to scan the affected system for additional indicators of compromise or malicious activity, focusing on defense evasion techniques.
* Monitor network traffic for signs of WPAD spoofing or other related attacks, and implement network segmentation to limit the impact of potential threats.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Update security policies and procedures to include specific measures for monitoring and protecting the DNS Global Query Block List, ensuring rapid detection and response to similar threats in the future.


## Rule query [_rule_query_270]

```js
registry where host.os.type == "windows" and event.type == "change" and
(
  (registry.value : "EnableGlobalQueryBlockList" and registry.data.strings : ("0", "0x00000000")) or
  (registry.value : "GlobalQueryBlockList" and not registry.data.strings : "wpad")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Adversary-in-the-Middle
    * ID: T1557
    * Reference URL: [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/techniques/T1557/)



