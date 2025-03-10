---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-smtp-on-port-26-tcp.html
---

# SMTP on Port 26/TCP [prebuilt-rule-8-17-4-smtp-on-port-26-tcp]

This rule detects events that may indicate use of SMTP on TCP port 26. This port is commonly used by several popular mail transfer agents to deconflict with the default SMTP port 25. This port has also been used by a malware family called BadPatch for command and control of Windows systems.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.panos*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/unit42-badpatch/](https://unit42.paloaltonetworks.com/unit42-badpatch/)
* [https://isc.sans.edu/forums/diary/Next+up+whats+up+with+TCP+port+26/25564/](https://isc.sans.edu/forums/diary/Next+up+whats+up+with+TCP+port+26/25564/)

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

## Investigation guide [_investigation_guide_4652]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SMTP on Port 26/TCP**

SMTP, typically operating on port 25, is crucial for email transmission. However, port 26 is often used to avoid conflicts or restrictions on port 25. Adversaries exploit this by using port 26 for covert command and control, as seen with the BadPatch malware. The detection rule identifies suspicious SMTP activity on port 26 by analyzing network traffic patterns, helping to uncover potential threats.

**Possible investigation steps**

* Review the network traffic logs to identify any unusual patterns or anomalies associated with TCP port 26, focusing on the event.dataset fields such as network_traffic.flow or zeek.smtp.
* Analyze the source and destination IP addresses involved in the alert to determine if they are known or associated with any previous suspicious activities.
* Check for any additional alerts or logs related to the same source or destination IP addresses to identify potential patterns or repeated attempts of communication on port 26.
* Investigate the context of the communication by examining the payload data, if available, to identify any indicators of compromise or malicious content.
* Correlate the findings with threat intelligence sources to determine if the IP addresses or domains are associated with known threat actors or malware, such as BadPatch.
* Assess the risk and impact on the affected systems by determining if any sensitive data or critical systems are involved in the communication on port 26.

**False positive analysis**

* Legitimate mail transfer agents may use port 26 to avoid conflicts with port 25. Identify these agents and create exceptions in the detection rule to prevent unnecessary alerts.
* Some network configurations might reroute SMTP traffic to port 26 for load balancing or security reasons. Verify these configurations and whitelist known IP addresses or domains to reduce false positives.
* Internal testing or development environments might use port 26 for non-malicious purposes. Document these environments and exclude their traffic from triggering alerts.
* Certain email service providers may use port 26 as an alternative to port 25. Confirm these providers and adjust the rule to recognize their traffic as benign.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further command and control communication via port 26.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove the BadPatch malware or any other malicious software.
* Review and analyze network logs to identify any other systems that may have communicated with the same command and control server, and isolate those systems as well.
* Change all passwords and credentials that may have been compromised or accessed by the affected system to prevent unauthorized access.
* Apply security patches and updates to the affected system and any other vulnerable systems to mitigate exploitation by similar threats.
* Monitor network traffic for any further suspicious activity on port 26 and other non-standard ports, adjusting firewall rules to block unauthorized SMTP traffic.
* Escalate the incident to the security operations center (SOC) or relevant cybersecurity team for further investigation and to ensure comprehensive threat eradication.


## Rule query [_rule_query_5607]

```js
(event.dataset: (network_traffic.flow or zeek.smtp) or event.category:(network or network_traffic)) and network.transport:tcp and destination.port:26
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Alternative Protocol
    * ID: T1048
    * Reference URL: [https://attack.mitre.org/techniques/T1048/](https://attack.mitre.org/techniques/T1048/)



