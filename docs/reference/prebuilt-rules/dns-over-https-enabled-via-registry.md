---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/dns-over-https-enabled-via-registry.html
---

# DNS-over-HTTPS Enabled via Registry [dns-over-https-enabled-via-registry]

Identifies when a user enables DNS-over-HTTPS. This can be used to hide internet activity or the process of exfiltrating data. With this enabled, an organization will lose visibility into data such as query type, response, and originating IP, which are used to determine bad actors.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html](https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.md)
* [https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode](https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_261]

**Triage and analysis**

[TBC: QUOTE]
**Investigating DNS-over-HTTPS Enabled via Registry**

DNS-over-HTTPS (DoH) encrypts DNS queries to enhance privacy and security, preventing eavesdropping and manipulation. However, adversaries can exploit DoH to conceal malicious activities, such as data exfiltration, by bypassing traditional DNS monitoring. The detection rule identifies registry changes enabling DoH in browsers like Edge, Chrome, and Firefox, signaling potential misuse for defense evasion.

**Possible investigation steps**

* Review the registry path and data values from the alert to determine which browser and setting were modified. Check if the change aligns with known user activity or policy.
* Investigate the user account associated with the registry change to assess if the activity is expected or if the account has a history of suspicious behavior.
* Examine recent network traffic from the host to identify any unusual or unauthorized DNS queries that could indicate data exfiltration or other malicious activities.
* Check for any other recent registry changes or system modifications on the host that might suggest further attempts at defense evasion or persistence.
* Correlate the alert with other security events or logs from the same host or user to identify patterns or additional indicators of compromise.

**False positive analysis**

* Legitimate software updates or installations may enable DNS-over-HTTPS settings in browsers. Monitor software update schedules and correlate registry changes with known update events to identify benign changes.
* Organizational policies might require DNS-over-HTTPS for privacy compliance. Document these policies and create exceptions in the detection rule for systems where this is a known requirement.
* User-initiated privacy settings changes can trigger the rule. Educate users on the implications of enabling DNS-over-HTTPS and establish a process for them to report intentional changes, allowing for exclusion of these events.
* Security tools or privacy-focused applications may enable DNS-over-HTTPS as part of their functionality. Identify these tools within the organization and adjust the detection rule to exclude registry changes associated with their operation.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential data exfiltration or further malicious activity.
* Review and revert any unauthorized registry changes related to DNS-over-HTTPS settings in Edge, Chrome, and Firefox to restore standard DNS monitoring capabilities.
* Conduct a thorough scan of the affected system using updated antivirus and endpoint detection tools to identify and remove any malicious software or scripts.
* Analyze network traffic logs to identify any unusual or unauthorized DNS queries or data transfers that may have occurred during the period of DoH activation.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring for registry changes related to DNS settings across the organization to detect similar threats in the future.
* Review and update security policies to ensure that DNS-over-HTTPS is only enabled through approved channels and for legitimate purposes, reducing the risk of misuse.


## Rule query [_rule_query_271]

```js
registry where host.os.type == "windows" and event.type == "change" and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : ("1", "0x00000001"))
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



