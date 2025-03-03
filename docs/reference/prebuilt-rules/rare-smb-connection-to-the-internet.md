---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/rare-smb-connection-to-the-internet.html
---

# Rare SMB Connection to the Internet [rare-smb-connection-to-the-internet]

This rule detects rare internet network connections via the SMB protocol. SMB is commonly used to leak NTLM credentials via rogue UNC path injection.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.network-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/](https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Exfiltration
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_860]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Rare SMB Connection to the Internet**

Server Message Block (SMB) is a protocol used for sharing files and printers within a network. Adversaries exploit SMB to exfiltrate data by injecting rogue paths to capture NTLM credentials. The detection rule identifies unusual SMB traffic from internal IPs to external networks, flagging potential exfiltration attempts by monitoring specific ports and excluding known safe IP ranges.

**Possible investigation steps**

* Review the alert details to identify the internal source IP address involved in the SMB connection and verify if it belongs to a known or authorized device within the organization.
* Check the destination IP address to determine if it is associated with any known malicious activity or if it belongs to an external network that should not be receiving SMB traffic from internal systems.
* Investigate the process with PID 4 on the source host, which typically corresponds to the Windows System process, to identify any unusual activity or recent changes that could indicate compromise or misuse.
* Analyze network logs to trace the SMB traffic flow and identify any patterns or additional connections that may suggest data exfiltration attempts.
* Correlate the alert with other security events or logs from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context and determine if this is part of a larger attack campaign.
* Consult with the IT or network team to verify if there are any legitimate business reasons for the detected SMB traffic to the external network, and if not, consider blocking the connection and conducting a deeper investigation into the source host.

**False positive analysis**

* Internal network scanning tools may trigger alerts if they simulate SMB traffic to external IPs. Exclude IPs associated with these tools from the rule to prevent false positives.
* Legitimate business applications that require SMB connections to external cloud services might be flagged. Identify and whitelist these specific external IPs or domains to avoid unnecessary alerts.
* Backup solutions that use SMB for data transfer to offsite locations can be mistaken for exfiltration attempts. Ensure these backup service IPs are added to the exception list.
* Misconfigured network devices that inadvertently route SMB traffic externally could cause false alerts. Regularly audit and correct device configurations to minimize these occurrences.
* Security testing or penetration testing activities might generate SMB traffic to external IPs. Coordinate with security teams to temporarily disable the rule or add exceptions during testing periods.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further data exfiltration or lateral movement.
* Conduct a thorough review of the host’s network connections and processes to identify any unauthorized SMB traffic or suspicious activities.
* Reset credentials for any accounts that may have been exposed or compromised, focusing on those with elevated privileges.
* Apply patches and updates to the affected system and any other vulnerable systems to mitigate known SMB vulnerabilities.
* Implement network segmentation to limit SMB traffic to only necessary internal communications, reducing the risk of external exposure.
* Enhance monitoring and logging for SMB traffic, particularly for connections to external IPs, to detect and respond to future anomalies more effectively.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_917]

```js
event.category:network and host.os.type:windows and process.pid:4 and
  network.transport:tcp and destination.port:(139 or 445) and
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

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Alternative Protocol
    * ID: T1048
    * Reference URL: [https://attack.mitre.org/techniques/T1048/](https://attack.mitre.org/techniques/T1048/)



