---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/ipsec-nat-traversal-port-activity.html
---

# IPSEC NAT Traversal Port Activity [ipsec-nat-traversal-port-activity]

This rule detects events that could be describing IPSEC NAT Traversal traffic. IPSEC is a VPN technology that allows one system to talk to another using encrypted tunnels. NAT Traversal enables these tunnels to communicate over the Internet where one of the sides is behind a NAT router gateway. This may be common on your network, but this technique is also used by threat actors to avoid detection.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Tactic: Command and Control
* Domain: Endpoint
* Use Case: Threat Detection
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_420]

**Triage and analysis**

[TBC: QUOTE]
**Investigating IPSEC NAT Traversal Port Activity**

IPSEC NAT Traversal facilitates secure VPN communication across NAT devices by encapsulating IPSEC packets in UDP, typically using port 4500. While essential for legitimate encrypted traffic, adversaries exploit this to mask malicious activities, bypassing network defenses. The detection rule identifies unusual UDP traffic on port 4500, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the source and destination IP addresses associated with the UDP traffic on port 4500 to determine if they are known or expected within your network environment.
* Analyze the volume and frequency of the detected traffic to assess whether it aligns with typical IPSEC NAT Traversal usage or if it appears anomalous.
* Check for any associated network traffic events in the same timeframe that might indicate a pattern of suspicious activity, such as unusual data transfer volumes or connections to known malicious IP addresses.
* Investigate the endpoint or device generating the traffic to verify if it is authorized to use IPSEC NAT Traversal and if it has any history of security incidents or vulnerabilities.
* Correlate the detected activity with any recent changes in network configurations or security policies that might explain the traffic pattern.
* Consult threat intelligence sources to determine if the destination IP address or domain has been associated with known threat actors or command and control infrastructure.

**False positive analysis**

* Legitimate VPN traffic using IPSEC NAT Traversal can trigger alerts. Regularly review and whitelist known IP addresses or subnets associated with authorized VPN connections to reduce false positives.
* Network devices or services that rely on IPSEC for secure communication may generate expected traffic on port 4500. Identify and document these devices, then create exceptions in the detection rule to prevent unnecessary alerts.
* Automated backup or synchronization services that use IPSEC for secure data transfer might be flagged. Monitor these services and exclude their traffic patterns if they are verified as non-threatening.
* Some enterprise applications may use IPSEC NAT Traversal for secure communication. Conduct an inventory of such applications and adjust the rule to exclude their traffic after confirming their legitimacy.
* Regularly update the list of known safe IP addresses and services to ensure that new legitimate sources of IPSEC NAT Traversal traffic are promptly excluded from triggering alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further potential malicious activity and lateral movement.
* Conduct a thorough analysis of the isolated system to identify any signs of compromise, such as unauthorized access or data exfiltration, focusing on logs and network traffic related to UDP port 4500.
* Block all suspicious IP addresses associated with the detected traffic on port 4500 at the network perimeter to prevent further communication with potential threat actors.
* Review and update firewall and intrusion detection/prevention system (IDS/IPS) rules to ensure they effectively block unauthorized IPSEC NAT Traversal traffic, particularly on UDP port 4500.
* Restore the affected system from a known good backup if any signs of compromise are confirmed, ensuring that all security patches and updates are applied before reconnecting to the network.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for UDP traffic on port 4500 to detect and respond to any future suspicious activity promptly.


## Rule query [_rule_query_452]

```js
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and network.transport:udp and destination.port:4500
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)



