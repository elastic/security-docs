---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-network-connection-via-dllhost.html
---

# Unusual Network Connection via DllHost [unusual-network-connection-via-dllhost]

Identifies unusual instances of dllhost.exe making outbound network connections. This may indicate adversarial Command and Control activity.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)
* [https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/](https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/)
* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1135]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Network Connection via DllHost**

Dllhost.exe is a legitimate Windows process used to host DLL services. Adversaries may exploit it for stealthy command and control by initiating unauthorized network connections. The detection rule identifies suspicious dllhost.exe activity by monitoring outbound connections to non-local IPs, which may indicate malicious intent. This approach helps in identifying potential threats by focusing on unusual network behaviors associated with this process.

**Possible investigation steps**

* Review the process start event for dllhost.exe to confirm its legitimacy by checking the process arguments and the parent process that initiated it.
* Analyze the destination IP addresses involved in the network connections to determine if they are known malicious or suspicious entities, using threat intelligence sources.
* Check the timeline of events to see if there are any other unusual activities on the host around the time of the dllhost.exe network connection, such as other process executions or file modifications.
* Investigate the user account associated with the dllhost.exe process to determine if there are any signs of compromise or unauthorized access.
* Examine the network traffic patterns from the host to identify any other unusual outbound connections that might indicate broader malicious activity.

**False positive analysis**

* Legitimate software updates or system maintenance tasks may cause dllhost.exe to make outbound connections. Users can monitor and whitelist known update servers to prevent these from being flagged.
* Certain enterprise applications might use dllhost.exe for legitimate network communications. Identify and document these applications, then create exceptions for their known IP addresses.
* Automated scripts or administrative tools that leverage dllhost.exe for network tasks can trigger false positives. Review and exclude these scripts or tools by specifying their associated IP ranges.
* Cloud-based services or virtual environments might route traffic through dllhost.exe. Verify these services and exclude their IP addresses from the detection rule to avoid unnecessary alerts.

**Response and remediation**

* Isolate the affected host from the network immediately to prevent further unauthorized communications and potential lateral movement.
* Terminate the suspicious dllhost.exe process to stop any ongoing malicious activity and prevent further outbound connections.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious software or artifacts.
* Review and analyze the network logs to identify any other systems that may have been targeted or compromised, and apply similar containment measures if necessary.
* Restore the affected system from a known good backup to ensure that any potential backdoors or persistent threats are removed.
* Implement network segmentation to limit the ability of similar threats to spread across the network in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional organizational measures are required.


## Rule query [_rule_query_1178]

```js
sequence by host.id, process.entity_id with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "dllhost.exe" and process.args_count == 1]
  [network where host.os.type == "windows" and process.name : "dllhost.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
    "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
    "FF00::/8")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



