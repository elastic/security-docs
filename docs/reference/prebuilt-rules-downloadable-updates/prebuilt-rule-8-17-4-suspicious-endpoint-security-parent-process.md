---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-endpoint-security-parent-process.html
---

# Suspicious Endpoint Security Parent Process [prebuilt-rule-8-17-4-suspicious-endpoint-security-parent-process]

A suspicious Endpoint Security parent process was detected. This may indicate a process hollowing or other form of code injection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4772]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Endpoint Security Parent Process**

Endpoint security solutions, like Elastic and Microsoft Defender, monitor and protect systems by analyzing process behaviors. Adversaries may exploit these processes through techniques like process hollowing, where malicious code is injected into legitimate processes to evade detection. The detection rule identifies anomalies by flagging unexpected parent processes of security executables, excluding known benign paths and arguments, thus highlighting potential threats.

**Possible investigation steps**

* Review the process details for the flagged executable (e.g., esensor.exe or elastic-endpoint.exe) to understand its expected behavior and any recent changes in its configuration or deployment.
* Examine the parent process executable path and name to determine if it is a known legitimate process or potentially malicious. Pay special attention to paths not listed in the known benign paths, such as those outside "?:\Program Files\Elastic*" or "?:\Windows\System32\*".
* Investigate the command-line arguments used by the parent process to identify any unusual or suspicious patterns that could indicate malicious activity, especially if they do not match the benign arguments like "test", "version", or "status".
* Check the historical activity of the parent process to see if it has been involved in other suspicious activities or if it has a history of spawning security-related processes.
* Correlate the alert with other security events or logs from data sources like Elastic Endgame, Microsoft Defender for Endpoint, or Sysmon to gather additional context and identify any related suspicious activities.
* Assess the risk and impact of the alert by considering the environment, the criticality of the affected systems, and any potential data exposure or operational disruption.

**False positive analysis**

* Security tools or scripts that automate tasks may trigger false positives if they launch endpoint security processes with unexpected parent processes. To manage this, identify and document these tools, then add their parent executable paths to the exclusion list.
* System administrators or IT personnel may use command-line tools like PowerShell or cmd.exe for legitimate maintenance tasks. If these tasks frequently trigger alerts, consider adding specific command-line arguments used in these tasks to the exclusion list.
* Software updates or installations might temporarily cause unexpected parent processes for security executables. Monitor these activities and, if they are routine and verified, add the associated parent executable paths to the exclusion list.
* Custom scripts or third-party applications that interact with security processes can also lead to false positives. Review these scripts or applications, and if they are deemed safe, include their parent executable paths in the exclusion list.
* Regularly review and update the exclusion list to ensure it reflects the current environment and operational practices, minimizing the risk of overlooking new legitimate processes.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate the suspicious process identified by the alert to stop any ongoing malicious activity and prevent further code execution.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized changes or additional malicious files.
* Restore the system from a known good backup if any malicious activity or unauthorized changes are confirmed, ensuring that the backup is clean and uncompromised.
* Update endpoint security solutions and apply any available patches to address vulnerabilities that may have been exploited by the adversary.
* Monitor the network and systems for any signs of re-infection or similar suspicious activities, using enhanced logging and alerting based on the identified threat indicators.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems may be affected.


## Rule query [_rule_query_5727]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("esensor.exe", "elastic-endpoint.exe") and
  process.parent.executable != null and
  /* add FPs here */
  not process.parent.executable : (
        "?:\\Program Files\\Elastic\\*",
        "?:\\Windows\\System32\\services.exe",
        "?:\\Windows\\System32\\WerFault*.exe",
        "?:\\Windows\\System32\\wermgr.exe",
        "?:\\Windows\\explorer.exe"
  ) and
  not (
    process.parent.executable : (
        "?:\\Windows\\System32\\cmd.exe",
        "?:\\Windows\\System32\\SecurityHealthHost.exe",
        "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ) and
    process.args : (
        "test", "version",
        "top", "run",
        "*help", "status",
        "upgrade", "/launch",
        "/enable"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)



