---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-rdp-remote-desktop-protocol-from-the-internet.html
---

# RDP (Remote Desktop Protocol) from the Internet [prebuilt-rule-8-17-4-rdp-remote-desktop-protocol-from-the-internet]

This rule detects network events that may indicate the use of RDP traffic from the Internet. RDP is commonly used by system administrators to remotely control a system for maintenance or to use shared resources. It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.panos*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Tactic: Command and Control
* Domain: Endpoint
* Use Case: Threat Detection
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4653]

**Triage and analysis**

[TBC: QUOTE]
**Investigating RDP (Remote Desktop Protocol) from the Internet**

RDP allows administrators to remotely manage systems, but exposing it to the internet poses security risks. Adversaries exploit RDP for unauthorized access, often using it as an entry point for attacks. The detection rule identifies suspicious RDP traffic by monitoring TCP connections on port 3389 from external IPs, flagging potential threats for further investigation.

**Possible investigation steps**

* Review the source IP address flagged in the alert to determine if it is known or associated with any previous malicious activity. Check threat intelligence sources for any reported malicious behavior.
* Analyze the destination IP address to confirm it belongs to your internal network (10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16) and identify the specific system targeted by the RDP connection.
* Examine network logs for any unusual or unexpected RDP traffic patterns from the source IP, such as repeated connection attempts or connections at odd hours, which may indicate brute force attempts or unauthorized access.
* Check for any recent changes or updates to firewall rules or security policies that might have inadvertently exposed RDP to the internet.
* Investigate the user accounts involved in the RDP session to ensure they are legitimate and have not been compromised. Look for any signs of unauthorized access or privilege escalation.
* Correlate the RDP traffic with other security events or alerts to identify any potential lateral movement or further malicious activity within the network.

**False positive analysis**

* Internal testing or maintenance activities may trigger the rule if RDP is temporarily exposed to the internet. To manage this, create exceptions for known internal IP addresses or scheduled maintenance windows.
* Legitimate third-party vendors or partners accessing systems via RDP for support purposes can be mistaken for threats. Establish a list of trusted external IP addresses and exclude them from the rule.
* Misconfigured network devices or security tools might inadvertently expose RDP to the internet, leading to false positives. Regularly audit network configurations and update the rule to exclude known benign sources.
* Cloud-based services or remote work solutions that use RDP over the internet can be flagged. Identify and whitelist these services' IP ranges to prevent unnecessary alerts.

**Response and remediation**

* Immediately block the external IP address identified in the alert from accessing the network to prevent further unauthorized RDP connections.
* Isolate the affected system from the network to contain any potential compromise and prevent lateral movement by the threat actor.
* Conduct a thorough review of the affected system for signs of compromise, such as unauthorized user accounts, changes in system configurations, or the presence of malware.
* Reset credentials for any accounts that were accessed or potentially compromised during the incident to prevent unauthorized access.
* Apply security patches and updates to the affected system and any other systems with RDP enabled to mitigate known vulnerabilities.
* Implement network segmentation to restrict RDP access to only trusted internal IP addresses and consider using a VPN for secure remote access.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_5608]

```js
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and
  network.transport:tcp and (destination.port:3389 or event.dataset:zeek.rdp) and
  not source.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  ) and
  destination.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



