---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/vnc-virtual-network-computing-to-the-internet.html
---

# VNC (Virtual Network Computing) to the Internet [vnc-virtual-network-computing-to-the-internet]

This rule detects network events that may indicate the use of VNC traffic to the Internet. VNC is commonly used by system administrators to remotely control a system for maintenance or to use shared resources. It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.

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

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1179]

**Triage and analysis**

[TBC: QUOTE]
**Investigating VNC (Virtual Network Computing) to the Internet**

VNC is a tool that allows remote control of computers, often used by administrators for maintenance. However, when exposed to the internet, it becomes a target for attackers seeking unauthorized access. Adversaries exploit VNC to establish backdoors or gain initial access. The detection rule identifies suspicious VNC traffic by monitoring specific TCP ports and filtering out internal IP addresses, flagging potential threats when VNC is accessed from external networks.

**Possible investigation steps**

* Review the source IP address to determine if it belongs to a known internal asset or user, and verify if the access was authorized.
* Check the destination IP address to confirm if it is an external address and investigate its reputation or any known associations with malicious activity.
* Analyze the network traffic logs for the specified TCP ports (5800-5810) to identify any unusual patterns or volumes of VNC traffic.
* Correlate the VNC traffic event with other security events or logs to identify any related suspicious activities or anomalies.
* Investigate the user account associated with the VNC session to ensure it has not been compromised or misused.
* Assess the system or application logs on the destination machine for any signs of unauthorized access or changes during the time of the VNC connection.

**False positive analysis**

* Internal maintenance activities may trigger the rule if VNC is used for legitimate remote administration. To manage this, create exceptions for known internal IP addresses that frequently use VNC for maintenance.
* Automated scripts or tools that use VNC for legitimate purposes might be flagged. Identify these tools and whitelist their IP addresses to prevent unnecessary alerts.
* Testing environments that simulate external access to VNC for security assessments can cause false positives. Exclude IP ranges associated with these environments to avoid confusion.
* Cloud-based services that use VNC for remote management might be misidentified as threats. Verify these services and add their IP addresses to an exception list if they are trusted.
* Temporary remote access setups for troubleshooting or support can be mistaken for unauthorized access. Document these instances and apply temporary exceptions to reduce false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any active VNC sessions that are identified as originating from external networks to cut off potential attacker access.
* Conduct a thorough review of system logs and network traffic to identify any unauthorized access or data transfer that may have occurred during the VNC exposure.
* Change all passwords and credentials associated with the affected system and any other systems that may have been accessed using the same credentials.
* Apply necessary patches and updates to the VNC software and any other vulnerable applications on the affected system to mitigate known vulnerabilities.
* Implement network segmentation to ensure that VNC services are only accessible from trusted internal networks and not exposed to the internet.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems may be compromised.


## Rule query [_rule_query_1202]

```js
(event.dataset: network_traffic.flow  or (event.category: (network or network_traffic))) and
  network.transport:tcp and destination.port >= 5800 and destination.port <= 5810 and
  source.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  ) and
  not destination.ip:(
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
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Remote Access Software
    * ID: T1219
    * Reference URL: [https://attack.mitre.org/techniques/T1219/](https://attack.mitre.org/techniques/T1219/)



