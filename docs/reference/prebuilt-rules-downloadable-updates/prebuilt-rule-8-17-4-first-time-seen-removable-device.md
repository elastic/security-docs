---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-first-time-seen-removable-device.html
---

# First Time Seen Removable Device [prebuilt-rule-8-17-4-first-time-seen-removable-device]

Identifies newly seen removable devices by device friendly name using registry modification events. While this activity is not inherently malicious, analysts can use those events to aid monitoring for data exfiltration over those devices.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.registry-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/USB-storage.html](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/USB-storage.md)
* [https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Exfiltration
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4868]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Time Seen Removable Device**

Removable devices, like USB drives, are common in Windows environments for data transfer. Adversaries exploit these to introduce malware or exfiltrate data, leveraging their plug-and-play nature. The detection rule monitors registry changes for new device names, signaling potential unauthorized access. By focusing on first-time-seen devices, it helps identify suspicious activities linked to data exfiltration or initial access attempts.

**Possible investigation steps**

* Review the registry event details to confirm the presence of a new device by checking the registry.value for "FriendlyName" and registry.path for USBSTOR.
* Correlate the timestamp of the registry event with user activity logs to identify which user was logged in at the time of the device connection.
* Check for any subsequent file access or transfer events involving the new device to assess potential data exfiltration.
* Investigate the device’s history by searching for any previous connections to other systems within the network to determine if it has been used elsewhere.
* Analyze any related alerts or logs from data sources like Elastic Endgame, Sysmon, or Microsoft Defender for Endpoint for additional context or suspicious activities linked to the device.

**False positive analysis**

* Frequent use of company-issued USB drives for legitimate data transfer can trigger alerts. Maintain a list of approved devices and create exceptions for these in the monitoring system.
* Software updates or installations via USB drives may be flagged. Identify and whitelist known update devices or processes to prevent unnecessary alerts.
* IT department activities involving USB devices for maintenance or troubleshooting can appear suspicious. Coordinate with IT to log and exclude these routine operations from triggering alerts.
* Devices used for regular backups might be detected as new. Ensure backup devices are registered and excluded from the rule to avoid false positives.
* Personal USB devices used by employees for non-work-related purposes can cause alerts. Implement a policy for registering personal devices and exclude them if deemed non-threatening.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent potential data exfiltration or further spread of malware.
* Conduct a thorough scan of the isolated host using updated antivirus and anti-malware tools to identify and remove any malicious software introduced via the removable device.
* Review and analyze the registry changes logged by the detection rule to confirm the legitimacy of the device and assess any unauthorized access attempts.
* If malicious activity is confirmed, collect and preserve relevant logs and evidence for further forensic analysis and potential legal action.
* Notify the security team and relevant stakeholders about the incident, providing details of the device and any identified threats.
* Implement a temporary block on the use of removable devices across the network until the threat is fully contained and remediated.
* Enhance monitoring and detection capabilities by updating security tools and rules to better identify similar threats in the future, focusing on registry changes and device connections.


## Rule query [_rule_query_5823]

```js
event.category:"registry" and host.os.type:"windows" and registry.value:"FriendlyName" and registry.path:*USBSTOR*
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

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Physical Medium
    * ID: T1052
    * Reference URL: [https://attack.mitre.org/techniques/T1052/](https://attack.mitre.org/techniques/T1052/)

* Sub-technique:

    * Name: Exfiltration over USB
    * ID: T1052.001
    * Reference URL: [https://attack.mitre.org/techniques/T1052/001/](https://attack.mitre.org/techniques/T1052/001/)



