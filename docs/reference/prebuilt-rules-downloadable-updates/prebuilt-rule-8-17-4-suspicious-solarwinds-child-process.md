---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-solarwinds-child-process.html
---

# Suspicious SolarWinds Child Process [prebuilt-rule-8-17-4-suspicious-solarwinds-child-process]

A suspicious SolarWinds child process was detected, which may indicate an attempt to execute malicious programs.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.md)
* [https://github.com/mandiant/sunburst_countermeasures/blob/main/rules/SUNBURST/hxioc/SUNBURST%20SUSPICIOUS%20CHILD%20PROCESSES%20(METHODOLOGY).ioc](https://github.com/mandiant/sunburst_countermeasures/blob/main/rules/SUNBURST/hxioc/SUNBURST%20SUSPICIOUS%20CHILD%20PROCESSES%20(METHODOLOGY).ioc)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4832]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious SolarWinds Child Process**

SolarWinds is a widely used IT management software that operates critical network and system monitoring functions. Adversaries may exploit its trusted processes to execute unauthorized programs, leveraging its elevated privileges to bypass security controls. The detection rule identifies unusual child processes spawned by SolarWinds' core services, excluding known legitimate operations, to flag potential malicious activity.

**Possible investigation steps**

* Review the details of the triggered alert to identify the specific child process name and executable path that caused the alert.
* Check the parent process details, specifically SolarWinds.BusinessLayerHost.exe or SolarWinds.BusinessLayerHostx64.exe, to confirm its legitimacy and ensure it is running from the expected directory.
* Investigate the child process’s code signature to determine if it is trusted or if there are any anomalies in the signature that could indicate tampering.
* Analyze the historical activity of the suspicious child process on the host to identify any patterns or previous instances of execution that could provide context.
* Correlate the suspicious process activity with other security events or logs from the same host to identify any related malicious behavior or indicators of compromise.
* Consult threat intelligence sources to determine if the suspicious process or executable path is associated with known malware or adversary techniques.

**False positive analysis**

* Legitimate SolarWinds updates or patches may trigger the rule. Ensure that the process code signature is verified as trusted and matches known update signatures.
* Custom scripts or tools integrated with SolarWinds for automation purposes might be flagged. Review these processes and add them to the exclusion list if they are verified as safe and necessary for operations.
* Third-party plugins or extensions that interact with SolarWinds could be misidentified. Validate these plugins and consider excluding them if they are from a trusted source and essential for functionality.
* Scheduled tasks or maintenance activities that involve SolarWinds processes may appear suspicious. Confirm these tasks are part of regular operations and exclude them if they are consistent with expected behavior.
* Temporary diagnostic or troubleshooting tools used by IT staff might be detected. Ensure these tools are authorized and add them to the exclusion list if they are frequently used and pose no threat.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious child processes identified that are not part of the known legitimate operations list, ensuring that no malicious programs continue to execute.
* Conduct a thorough review of the affected system’s recent activity logs to identify any additional indicators of compromise or unauthorized changes.
* Restore the affected system from a known good backup to ensure that any potential malware or unauthorized changes are removed.
* Update all SolarWinds software and related components to the latest versions to patch any known vulnerabilities that could be exploited.
* Implement enhanced monitoring on the affected system and similar environments to detect any recurrence of suspicious activity, focusing on unusual child processes spawned by SolarWinds services.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if broader organizational impacts need to be addressed.


## Rule query [_rule_query_5787]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name: ("SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe") and
 not (
    process.name : (
        "APMServiceControl*.exe",
        "ExportToPDFCmd*.Exe",
        "SolarWinds.Credentials.Orion.WebApi*.exe",
        "SolarWinds.Orion.Topology.Calculator*.exe",
        "Database-Maint.exe",
        "SolarWinds.Orion.ApiPoller.Service.exe",
        "WerFault.exe",
        "WerMgr.exe",
        "SolarWinds.BusinessLayerHost.exe",
        "SolarWinds.BusinessLayerHostx64.exe",
        "SolarWinds.Topology.Calculator.exe",
        "SolarWinds.Topology.Calculatorx64.exe",
        "SolarWinds.APM.RealTimeProcessPoller.exe") and
    process.code_signature.trusted == true
 ) and
 not process.executable : ("?:\\Windows\\SysWOW64\\ARP.EXE", "?:\\Windows\\SysWOW64\\lodctr.exe", "?:\\Windows\\SysWOW64\\unlodctr.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Supply Chain Compromise
    * ID: T1195
    * Reference URL: [https://attack.mitre.org/techniques/T1195/](https://attack.mitre.org/techniques/T1195/)

* Sub-technique:

    * Name: Compromise Software Supply Chain
    * ID: T1195.002
    * Reference URL: [https://attack.mitre.org/techniques/T1195/002/](https://attack.mitre.org/techniques/T1195/002/)



