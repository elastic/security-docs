---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-rdp-activex-client-loaded.html
---

# Suspicious RDP ActiveX Client Loaded [prebuilt-rule-8-17-4-suspicious-rdp-activex-client-loaded]

Identifies suspicious Image Loading of the Remote Desktop Services ActiveX Client (mstscax), this may indicate the presence of RDP lateral movement capability.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*

**Severity**: medium

**Risk score**: 47

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
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4897]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious RDP ActiveX Client Loaded**

The Remote Desktop Services ActiveX Client, mstscax.dll, facilitates remote desktop connections, enabling users to access and control other systems. Adversaries may exploit this by loading the DLL in unauthorized contexts to move laterally within a network. The detection rule identifies unusual loading of mstscax.dll outside typical system paths, flagging potential misuse indicative of lateral movement attempts.

**Possible investigation steps**

* Review the process executable path to determine if mstscax.dll was loaded from an unusual or unauthorized location, as specified in the query.
* Check the associated process and user context to identify who initiated the process and whether it aligns with expected behavior or known user activity.
* Investigate the network connections associated with the process to identify any suspicious remote connections or lateral movement attempts.
* Examine recent login events and RDP session logs for the involved user account to detect any unauthorized access or anomalies.
* Correlate the alert with other security events or logs to identify potential patterns or related suspicious activities within the network.

**False positive analysis**

* Legitimate administrative tools or scripts that load mstscax.dll from non-standard paths may trigger false positives. To mitigate this, identify and document these tools, then add their paths to the exclusion list in the detection rule.
* Software updates or installations that temporarily load mstscax.dll from unusual locations can cause false alerts. Monitor and log these activities, and consider excluding these paths if they are consistently flagged during known update periods.
* Virtualization software or sandbox environments that use mstscax.dll for legitimate purposes might be flagged. Verify the use of such software and exclude their executable paths from the rule to prevent unnecessary alerts.
* Custom user scripts or automation tasks that involve remote desktop functionalities may load mstscax.dll in unexpected ways. Review these scripts and, if deemed safe, add their execution paths to the exclusion list to reduce noise.
* Network drive mappings or shared folders that involve remote desktop components could lead to false positives. Ensure these are part of regular operations and exclude their paths if they are frequently flagged without malicious intent.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further lateral movement by the adversary.
* Terminate any suspicious processes associated with the unauthorized loading of mstscax.dll to halt potential malicious activities.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malware or unauthorized software.
* Review and analyze the system and network logs to identify any other systems that may have been accessed or compromised by the adversary.
* Reset credentials for any accounts that were accessed or potentially compromised during the incident to prevent unauthorized access.
* Implement network segmentation to limit the ability of adversaries to move laterally within the network in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data have been affected.


## Setup [_setup_1550]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5852]

```js
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : "mstscax.dll" or file.name : "mstscax.dll") and
   /* depending on noise in your env add here extra paths  */
  process.executable : (
    "C:\\Windows\\*",
    "C:\\Users\\Public\\*",
    "C:\\Users\\Default\\*",
    "C:\\Intel\\*",
    "C:\\PerfLogs\\*",
    "C:\\ProgramData\\*",
    "\\Device\\Mup\\*",
    "\\\\*"
  ) and
  /* add here FPs */
  not process.executable : (
    "?:\\Windows\\System32\\mstsc.exe",
    "?:\\Windows\\SysWOW64\\mstsc.exe",
    "?:\\Windows\\System32\\vmconnect.exe",
    "?:\\Windows\\System32\\WindowsSandboxClient.exe",
    "?:\\Windows\\System32\\hvsirdpclient.exe"
  )
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



