---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-from-a-removable-media-with-network-connection.html
---

# Execution from a Removable Media with Network Connection [execution-from-a-removable-media-with-network-connection]

Identifies process execution from a removable media and by an unusual process. Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_309]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution from a Removable Media with Network Connection**

Removable media, like USB drives, are often used for data transfer but can be exploited by adversaries to introduce malware into isolated systems. Attackers may leverage autorun features to execute malicious code upon insertion. The detection rule identifies suspicious process executions from USB devices, especially those lacking valid code signatures, and correlates them with network connection attempts, signaling potential unauthorized access efforts.

**Possible investigation steps**

* Review the process execution details, focusing on the process.entity_id to identify the specific process that was executed from the USB device.
* Check the process.Ext.device.bus_type and process.Ext.device.product_id fields to confirm the involvement of a USB device and gather information about the specific device used.
* Investigate the process.code_signature fields to determine if the process lacks a valid code signature, which could indicate malicious intent.
* Correlate the process execution with network connection attempts by examining the network event logs, particularly looking for any unusual or unauthorized connection attempts.
* Assess the context of the network connection attempt, including the destination IP address and port, to evaluate the potential risk and intent of the connection.
* Gather additional context by reviewing recent activity on the host, such as other process executions or file modifications, to identify any further signs of compromise.
* If necessary, isolate the affected system to prevent further unauthorized access or data exfiltration while continuing the investigation.

**False positive analysis**

* Legitimate software installations from USB drives may trigger the rule. To manage this, create exceptions for known software installers by verifying their code signatures and adding them to an allowlist.
* IT administrators often use USB devices for system updates or maintenance. Identify and exclude these activities by correlating them with known administrator accounts or devices.
* Some organizations use USB devices for regular data transfers. Establish a baseline of normal USB activity and exclude these patterns from triggering alerts.
* Devices with expired but previously trusted code signatures might be flagged. Regularly update the list of trusted certificates and exclude processes with known expired signatures that are still considered safe.
* Network connection attempts by legitimate applications running from USB drives can be mistaken for threats. Monitor and document these applications, then configure exceptions based on their process names and network behavior.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Disable autorun features on all systems to prevent automatic execution of potentially malicious code from removable media.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malware.
* Review and block any suspicious network connections originating from the affected system to prevent communication with potential command and control servers.
* Collect and preserve relevant logs and forensic evidence from the affected system and removable media for further analysis and potential legal action.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine if other systems may be affected.
* Implement enhanced monitoring and alerting for similar activities, focusing on process executions from removable media and unauthorized network connection attempts.


## Rule query [_rule_query_324]

```js
sequence by process.entity_id with maxspan=5m
 [process where host.os.type == "windows" and event.action == "start" and

  /* Direct Exec from USB */
  (process.Ext.device.bus_type : "usb" or process.Ext.device.product_id : "USB *") and
  (process.code_signature.trusted == false or process.code_signature.exists == false) and

  not process.code_signature.status : ("errorExpired", "errorCode_endpoint*")]
 [network where host.os.type == "windows" and event.action == "connection_attempted"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Replication Through Removable Media
    * ID: T1091
    * Reference URL: [https://attack.mitre.org/techniques/T1091/](https://attack.mitre.org/techniques/T1091/)



