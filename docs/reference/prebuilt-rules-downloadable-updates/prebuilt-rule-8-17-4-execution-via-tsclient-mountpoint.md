---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-execution-via-tsclient-mountpoint.html
---

# Execution via TSClient Mountpoint [prebuilt-rule-8-17-4-execution-via-tsclient-mountpoint]

Identifies execution from the Remote Desktop Protocol (RDP) shared mountpoint tsclient on the target host. This may indicate a lateral movement attempt.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3](https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3)
* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4886]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution via TSClient Mountpoint**

The TSClient mountpoint is a feature of the Remote Desktop Protocol (RDP) that allows users to access local drives from a remote session. Adversaries can exploit this by executing malicious files from the shared mountpoint, facilitating lateral movement within a network. The detection rule identifies such activities by monitoring for process executions originating from the TSClient path, signaling potential unauthorized access attempts.

**Possible investigation steps**

* Review the alert details to confirm the process execution path matches the pattern "\\Device\\Mup\\tsclient\\*.exe" and verify the host operating system is Windows.
* Identify the user account associated with the RDP session and check for any unusual or unauthorized access patterns, such as logins from unexpected locations or at odd times.
* Examine the executed process’s hash and compare it against known malicious hashes in threat intelligence databases to determine if the file is potentially harmful.
* Investigate the source system from which the RDP session originated to identify any signs of compromise or unauthorized access that could indicate lateral movement.
* Check for any additional suspicious activities on the target host, such as unexpected network connections or file modifications, that may correlate with the execution event.
* Review the security logs from data sources like Microsoft Defender for Endpoint or Sysmon for any related alerts or anomalies that could provide further context on the incident.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they are executed from a local drive mapped through TSClient. To manage this, create exceptions for known update processes or installation paths that are frequently used in your environment.
* IT administrative tasks performed via RDP sessions can also cause false positives. Identify and exclude specific administrative tools or scripts that are regularly executed from TSClient paths by trusted personnel.
* Automated backup or synchronization software that accesses local drives through RDP might be flagged. Review and whitelist these processes if they are part of routine operations.
* Development or testing activities involving remote execution of scripts or applications from TSClient can be mistaken for threats. Establish a list of approved development tools and paths to exclude from monitoring.
* Regularly review and update the list of exceptions to ensure that only verified and necessary exclusions are maintained, minimizing the risk of overlooking genuine threats.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further lateral movement and potential data exfiltration.
* Terminate any suspicious processes running from the TSClient path to halt any ongoing malicious activity.
* Conduct a thorough scan of the affected host using endpoint detection and response (EDR) tools to identify and remove any malicious files or artifacts.
* Review and analyze RDP logs and session details to identify unauthorized access attempts and determine the source of the intrusion.
* Reset credentials for any accounts that were accessed or potentially compromised during the incident to prevent unauthorized access.
* Implement network segmentation to limit RDP access to only necessary systems and users, reducing the attack surface for similar threats.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation efforts.


## Rule query [_rule_query_5841]

```js
process where host.os.type == "windows" and event.type == "start" and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Remote Desktop Protocol
    * ID: T1021.001
    * Reference URL: [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)



