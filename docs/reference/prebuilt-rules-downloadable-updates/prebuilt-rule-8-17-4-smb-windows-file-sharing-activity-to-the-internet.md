---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-smb-windows-file-sharing-activity-to-the-internet.html
---

# SMB (Windows File Sharing) Activity to the Internet [prebuilt-rule-8-17-4-smb-windows-file-sharing-activity-to-the-internet]

This rule detects network events that may indicate the use of Windows file sharing (also called SMB or CIFS) traffic to the Internet. SMB is commonly used within networks to share files, printers, and other system resources amongst trusted systems. It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector or for data exfiltration.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.panos*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Tactic: Initial Access
* Domain: Endpoint
* Use Case: Threat Detection
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4661]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SMB (Windows File Sharing) Activity to the Internet**

SMB, a protocol for sharing files and resources within trusted networks, is vulnerable when exposed to the Internet. Adversaries exploit it for unauthorized access or data theft. The detection rule identifies suspicious SMB traffic from internal IPs to external networks, flagging potential threats by monitoring specific ports and excluding known safe IP ranges.

**Possible investigation steps**

* Review the source IP address from the alert to identify the internal system initiating the SMB traffic. Check if this IP belongs to a known device or user within the organization.
* Investigate the destination IP address to determine if it is associated with any known malicious activity or if it belongs to a legitimate external service that might require SMB access.
* Analyze network logs to identify any patterns or anomalies in the SMB traffic, such as unusual data transfer volumes or repeated access attempts, which could indicate malicious activity.
* Check for any recent changes or updates on the source system that might explain the SMB traffic, such as new software installations or configuration changes.
* Correlate the alert with other security events or logs, such as authentication logs or endpoint security alerts, to gather additional context and determine if this is part of a broader attack or isolated incident.
* Consult threat intelligence sources to see if there are any known vulnerabilities or exploits related to the SMB traffic observed, which could provide insight into potential attack vectors.

**False positive analysis**

* Internal testing environments may generate SMB traffic to external IPs for legitimate reasons. Identify and whitelist these IPs to prevent false positives.
* Cloud services or remote backup solutions might use SMB for data transfer. Verify these services and add their IP ranges to the exception list if they are trusted.
* VPN connections can sometimes appear as external traffic. Ensure that VPN IP ranges are included in the list of known safe IPs to avoid misclassification.
* Misconfigured network devices might inadvertently route SMB traffic externally. Regularly audit network configurations and update the rule exceptions to include any legitimate device IPs.
* Some third-party applications may use SMB for updates or data synchronization. Confirm the legitimacy of these applications and exclude their associated IPs from the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of firewall and network configurations to ensure SMB traffic is not allowed to the Internet, and block any unauthorized outbound SMB traffic on ports 139 and 445.
* Perform a comprehensive scan of the isolated system for malware or unauthorized access tools, focusing on identifying any backdoors or persistence mechanisms.
* Reset credentials and review access permissions for any accounts that may have been compromised or used in the suspicious activity.
* Notify the security operations center (SOC) and relevant stakeholders about the incident for further analysis and potential escalation.
* Implement additional monitoring and logging for SMB traffic to detect any future unauthorized attempts to access the Internet.
* Review and update security policies and procedures to prevent similar incidents, ensuring that SMB services are only accessible within trusted network segments.


## Rule query [_rule_query_5616]

```js
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and
  network.transport:tcp and (destination.port:(139 or 445) or event.dataset:zeek.smb) and
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

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Alternative Protocol
    * ID: T1048
    * Reference URL: [https://attack.mitre.org/techniques/T1048/](https://attack.mitre.org/techniques/T1048/)



