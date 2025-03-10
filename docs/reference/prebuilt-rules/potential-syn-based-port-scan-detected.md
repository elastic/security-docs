---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-syn-based-port-scan-detected.html
---

# Potential SYN-Based Port Scan Detected [potential-syn-based-port-scan-detected]

This rule identifies a potential SYN-Based port scan. A SYN port scan is a technique employed by attackers to scan a target network for open ports by sending SYN packets to multiple ports and observing the response. Attackers use this method to identify potential entry points or services that may be vulnerable to exploitation, allowing them to launch targeted attacks or gain unauthorized access to the system or network, compromising its security and potentially leading to data breaches or further malicious activities. This rule proposes threshold logic to check for connection attempts from one source host to 10 or more destination ports using 2 or less packets per port.

**Rule type**: threshold

**Rule indices**:

* logs-endpoint.events.network-*
* logs-network_traffic.*
* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-panw.panos*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 5

**References**: None

**Tags**:

* Domain: Network
* Tactic: Discovery
* Tactic: Reconnaissance
* Use Case: Network Security Monitoring
* Data Source: Elastic Defend
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_769]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential SYN-Based Port Scan Detected**

SYN-based port scanning is a reconnaissance technique where attackers send SYN packets to multiple ports to identify open services. This method helps adversaries map network vulnerabilities for potential exploitation. The detection rule identifies such scans by flagging connection attempts from internal IPs to multiple ports with minimal packet exchange, indicating a low-risk reconnaissance activity.

**Possible investigation steps**

* Review the source IP address involved in the alert to determine if it belongs to a known or authorized device within the network. Check for any recent changes or unusual activity associated with this IP.
* Analyze the destination ports targeted by the scan to identify any patterns or specific services that may be of interest to the attacker. Determine if these ports are associated with critical or vulnerable services.
* Examine historical logs to identify any previous scanning activity from the same source IP or similar patterns of behavior. This can help establish whether the activity is part of a larger reconnaissance effort.
* Correlate the alert with other security events or alerts to assess if there is a broader attack campaign underway. Look for related alerts that might indicate subsequent exploitation attempts.
* Investigate the timing and frequency of the scan attempts to understand if they coincide with other suspicious activities or known attack windows. This can provide context on the attacker’s intent and urgency.
* Assess the network’s current security posture and ensure that appropriate defenses, such as firewalls and intrusion detection systems, are configured to mitigate potential exploitation of identified open ports.

**False positive analysis**

* Internal network scanning tools or scripts used by IT teams for legitimate network mapping can trigger this rule. To manage this, create exceptions for known internal IP addresses or subnets used by IT for network discovery.
* Automated monitoring systems or security appliances that perform regular port checks might be flagged. Identify these systems and exclude their IP addresses from the rule to prevent false positives.
* Software updates or patch management systems that check multiple ports for service availability can be mistaken for a SYN-based port scan. Whitelist these systems to avoid unnecessary alerts.
* Load balancers or network devices that perform health checks across multiple ports may trigger the rule. Exclude these devices from the rule to ensure accurate detection.
* Development or testing environments where multiple port scans are part of routine operations can cause false positives. Implement exceptions for these environments to maintain focus on genuine threats.

**Response and remediation**

* Isolate the affected internal IP address to prevent further reconnaissance or potential exploitation of identified open ports.
* Conduct a thorough review of firewall and network access control lists to ensure that only necessary ports are open and accessible from internal networks.
* Implement rate limiting on SYN packets to reduce the risk of successful port scanning and reconnaissance activities.
* Monitor the network for any unusual outbound traffic from the affected IP address, which may indicate further malicious activity or data exfiltration attempts.
* Escalate the incident to the security operations team for further analysis and to determine if additional network segments or systems are affected.
* Update intrusion detection and prevention systems to enhance detection capabilities for similar SYN-based port scanning activities.
* Review and update network segmentation policies to limit the exposure of critical services and systems to internal reconnaissance activities.


## Rule query [_rule_query_817]

```js
destination.port : * and network.packets <= 2 and source.ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Service Discovery
    * ID: T1046
    * Reference URL: [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)

* Tactic:

    * Name: Reconnaissance
    * ID: TA0043
    * Reference URL: [https://attack.mitre.org/tactics/TA0043/](https://attack.mitre.org/tactics/TA0043/)

* Technique:

    * Name: Active Scanning
    * ID: T1595
    * Reference URL: [https://attack.mitre.org/techniques/T1595/](https://attack.mitre.org/techniques/T1595/)

* Sub-technique:

    * Name: Scanning IP Blocks
    * ID: T1595.001
    * Reference URL: [https://attack.mitre.org/techniques/T1595/001/](https://attack.mitre.org/techniques/T1595/001/)



