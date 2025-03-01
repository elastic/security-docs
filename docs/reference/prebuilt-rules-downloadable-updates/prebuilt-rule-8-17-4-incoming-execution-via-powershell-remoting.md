---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-incoming-execution-via-powershell-remoting.html
---

# Incoming Execution via PowerShell Remoting [prebuilt-rule-8-17-4-incoming-execution-via-powershell-remoting]

Identifies remote execution via Windows PowerShell remoting. Windows PowerShell remoting allows a user to run any Windows PowerShell command on one or more remote computers. This could be an indication of lateral movement.

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

* [https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4891]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Incoming Execution via PowerShell Remoting**

PowerShell Remoting enables administrators to execute commands on remote Windows systems, facilitating efficient management. However, adversaries can exploit this feature for lateral movement within a network. The detection rule identifies suspicious activity by monitoring network traffic on specific ports and processes initiated by PowerShell Remoting, flagging potential unauthorized remote executions.

**Possible investigation steps**

* Review the network traffic logs to identify the source IP address involved in the alert, ensuring it is not a known or authorized management system.
* Check the destination port (5985 or 5986) to confirm it aligns with PowerShell Remoting activity and verify if the connection was expected or authorized.
* Investigate the process tree on the affected host to determine if the process initiated by wsmprovhost.exe is legitimate or if it shows signs of suspicious activity.
* Examine the parent process of wsmprovhost.exe to identify any unusual or unauthorized processes that may have triggered the PowerShell Remoting session.
* Correlate the event with user activity logs to determine if the remote execution was performed by a legitimate user or if there are signs of compromised credentials.
* Assess the risk score and severity in the context of the organization’s environment to prioritize the response and determine if further containment or remediation actions are necessary.

**False positive analysis**

* Legitimate administrative tasks using PowerShell Remoting can trigger the rule. To manage this, identify and whitelist known administrative IP addresses or user accounts that frequently perform remote management tasks.
* Automated scripts or scheduled tasks that use PowerShell Remoting for system maintenance might be flagged. Review and document these scripts, then create exceptions for their specific process names or execution paths.
* Security tools or monitoring solutions that leverage PowerShell Remoting for legitimate purposes may cause alerts. Verify these tools and exclude their associated network traffic or processes from the detection rule.
* Internal IT support activities that involve remote troubleshooting using PowerShell Remoting can be mistaken for threats. Maintain a list of support personnel and their IP addresses to exclude them from triggering alerts.
* Regular software updates or patch management processes that utilize PowerShell Remoting should be considered. Identify these processes and exclude their network traffic or process executions to prevent false positives.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further lateral movement by the adversary.
* Terminate any suspicious PowerShell processes identified, especially those initiated by wsmprovhost.exe, to stop unauthorized remote executions.
* Conduct a thorough review of recent user activity and access logs on the affected host to identify any unauthorized access or changes.
* Reset credentials for any accounts that were used in the suspicious activity to prevent further unauthorized access.
* Apply patches and updates to the affected systems to address any vulnerabilities that may have been exploited.
* Enhance monitoring on the network for unusual activity on ports 5985 and 5986 to detect any future attempts at unauthorized PowerShell Remoting.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Rule query [_rule_query_5846]

```js
sequence by host.id with maxspan = 30s
   [network where host.os.type == "windows" and network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and
    event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
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

    * Name: Windows Remote Management
    * ID: T1021.006
    * Reference URL: [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



