---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-network-sweep-detected.html
---

# Potential Network Sweep Detected [prebuilt-rule-8-17-4-potential-network-sweep-detected]

This rule identifies a potential network sweep. A network sweep is a method used by attackers to scan a target network, identifying active hosts, open ports, and available services to gather information on vulnerabilities and weaknesses. This reconnaissance helps them plan subsequent attacks and exploit potential entry points for unauthorized access, data theft, or other malicious activities. This rule proposes threshold logic to check for connection attempts from one source host to 10 or more destination hosts on commonly used network services.

**Rule type**: threshold

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-endpoint.events.network-*
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

## Investigation guide [_investigation_guide_4656]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Network Sweep Detected**

Network sweeps are reconnaissance techniques where attackers scan networks to identify active hosts and services, often targeting common ports. This activity helps adversaries map out network vulnerabilities for future exploitation. The detection rule identifies such sweeps by monitoring connection attempts from a single source to multiple destinations on key ports, flagging potential reconnaissance activities for further investigation.

**Possible investigation steps**

* Review the source IP address to determine if it belongs to a known or trusted entity within the network, focusing on the private IP ranges specified in the query (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
* Analyze the destination IP addresses to identify any patterns or commonalities, such as specific subnets or devices, that could indicate targeted reconnaissance.
* Check historical logs for previous connection attempts from the same source IP to see if there is a pattern of repeated scanning behavior or if this is an isolated incident.
* Investigate the specific ports targeted (21, 22, 23, 25, 139, 445, 3389, 5985, 5986) to determine if they are associated with critical services or known vulnerabilities within the network.
* Correlate the detected activity with any recent changes or incidents in the network environment that might explain the behavior, such as new device deployments or configuration changes.
* Consult threat intelligence sources to determine if the source IP or similar scanning patterns have been associated with known threat actors or campaigns.

**False positive analysis**

* Internal network scans by IT teams can trigger the rule. Regularly scheduled scans for security assessments should be documented and their source IPs added to an exception list to prevent false alerts.
* Automated monitoring tools that check network health might cause false positives. Identify these tools and exclude their IP addresses from the rule to avoid unnecessary alerts.
* Load balancers or network devices that perform health checks across multiple hosts can be mistaken for network sweeps. Exclude these devices by adding their IPs to a whitelist.
* Development or testing environments where multiple connections are made for legitimate purposes can trigger the rule. Ensure these environments are recognized and their IP ranges are excluded from monitoring.
* Misconfigured devices that repeatedly attempt to connect to multiple hosts can appear as network sweeps. Investigate and correct the configuration, then exclude these devices if necessary.

**Response and remediation**

* Isolate the source IP: Immediately isolate the source IP address identified in the alert from the network to prevent further reconnaissance or potential exploitation of identified vulnerabilities.
* Block suspicious ports: Implement firewall rules to block incoming and outgoing traffic on the commonly targeted ports (21, 22, 23, 25, 139, 445, 3389, 5985, 5986) from the source IP to mitigate further scanning attempts.
* Conduct a network-wide scan: Perform a comprehensive scan of the network to identify any unauthorized access or changes that may have occurred as a result of the network sweep.
* Review and update access controls: Ensure that access controls and permissions are appropriately configured to limit exposure of critical services and sensitive data.
* Monitor for recurrence: Set up enhanced monitoring and alerting for any future connection attempts from the source IP or similar patterns of network sweep activity.
* Escalate to security operations: Notify the security operations team to conduct a deeper investigation into the source of the network sweep and assess any potential threats or breaches.
* Document and report: Record all findings, actions taken, and lessons learned in an incident report to inform future response strategies and improve network defenses.


## Rule query [_rule_query_5611]

```js
destination.port : (21 or 22 or 23 or 25 or 139 or 445 or 3389 or 5985 or 5986) and
source.ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
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



