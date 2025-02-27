---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-network-connection-via-msxsl.html
---

# Network Connection via MsXsl [prebuilt-rule-8-17-4-network-connection-via-msxsl]

Identifies msxsl.exe making a network connection. This may indicate adversarial activity as msxsl.exe is often leveraged by adversaries to execute malicious scripts and evade detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4783]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Connection via MsXsl**

MsXsl.exe is a legitimate Windows utility used to transform XML data using XSLT stylesheets. Adversaries exploit it to execute malicious scripts, bypassing security measures. The detection rule identifies suspicious network activity by MsXsl.exe, focusing on connections to non-local IPs, which may indicate unauthorized data exfiltration or command-and-control communication.

**Possible investigation steps**

* Review the process execution details for msxsl.exe, focusing on the process.entity_id and event.type fields to confirm the process start event and gather initial context.
* Analyze the network connection details, particularly the destination.ip field, to identify the external IP address msxsl.exe attempted to connect to and assess its reputation or any known associations with malicious activity.
* Check for any related alerts or logs involving the same process.entity_id to determine if msxsl.exe has been involved in other suspicious activities or if there are patterns of behavior indicating a broader attack.
* Investigate the parent process of msxsl.exe to understand how it was launched and whether it was initiated by a legitimate application or a potentially malicious script.
* Examine the system for any additional indicators of compromise, such as unusual file modifications or other processes making unexpected network connections, to assess the scope of potential adversarial activity.

**False positive analysis**

* Legitimate use of msxsl.exe for XML transformations in enterprise applications may trigger alerts. Users should identify and whitelist known applications or processes that use msxsl.exe for legitimate purposes.
* Automated scripts or scheduled tasks that utilize msxsl.exe for data processing can cause false positives. Review and document these tasks, then create exceptions for their network activity.
* Development or testing environments where msxsl.exe is used for debugging or testing XML transformations might be flagged. Ensure these environments are recognized and excluded from monitoring if they are verified as non-threatening.
* Internal network tools or monitoring solutions that leverage msxsl.exe for legitimate network communications should be identified. Add these tools to an exception list to prevent unnecessary alerts.
* Regularly review and update the list of excluded IP addresses to ensure that only trusted and verified internal IPs are exempt from triggering the rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized data exfiltration or command-and-control communication.
* Terminate the msxsl.exe process if it is still running to stop any ongoing malicious activity.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious scripts or files associated with msxsl.exe.
* Review and analyze the network logs to identify any other systems that may have been targeted or compromised by similar activity.
* Restore the affected system from a known good backup if any critical system files or configurations have been altered.
* Implement network segmentation to limit the ability of msxsl.exe or similar utilities to make unauthorized external connections in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data have been impacted.


## Rule query [_rule_query_5738]

```js
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "msxsl.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "msxsl.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: XSL Script Processing
    * ID: T1220
    * Reference URL: [https://attack.mitre.org/techniques/T1220/](https://attack.mitre.org/techniques/T1220/)



