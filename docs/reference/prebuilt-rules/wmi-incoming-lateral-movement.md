---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/wmi-incoming-lateral-movement.html
---

# WMI Incoming Lateral Movement [wmi-incoming-lateral-movement]

Identifies processes executed via Windows Management Instrumentation (WMI) on a remote host. This could be indicative of adversary lateral movement, but could be noisy if administrators use WMI to remotely manage hosts.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* winlogbeat-*
* logs-windows.sysmon_operational-*

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
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1187]

**Triage and analysis**

[TBC: QUOTE]
**Investigating WMI Incoming Lateral Movement**

Windows Management Instrumentation (WMI) is a core Windows feature enabling remote management and data collection. Adversaries exploit WMI for lateral movement by executing processes on remote hosts, often bypassing traditional security measures. The detection rule identifies suspicious WMI activity by monitoring specific network connections and process executions, filtering out common false positives to highlight potential threats.

**Possible investigation steps**

* Review the source IP address of the incoming RPC connection to determine if it is from a known or trusted network segment, excluding localhost addresses like 127.0.0.1 and ::1.
* Check the process name and parent process name, specifically looking for svchost.exe and WmiPrvSE.exe, to confirm the execution context and identify any unusual parent-child process relationships.
* Investigate the user ID associated with the process execution to ensure it is not a system account (S-1-5-18, S-1-5-19, S-1-5-20) and assess if the user has legitimate reasons for remote WMI activity.
* Examine the process executable path to verify it is not one of the excluded common false positives, such as those related to HPWBEM, SCCM, or other specified system utilities.
* Analyze the network connection details, including source and destination ports, to identify any patterns or anomalies that could indicate malicious lateral movement.
* Correlate the alert with other security events or logs from the same host or network segment to gather additional context and identify potential patterns of compromise.

**False positive analysis**

* Administrative use of WMI for remote management can trigger alerts. To manage this, create exceptions for known administrative accounts or specific IP addresses used by IT staff.
* Security tools like Nessus and SCCM may cause false positives. Exclude processes associated with these tools by adding their executables to the exception list.
* System processes running with high integrity levels might be flagged. Exclude processes with integrity levels marked as "System" to reduce noise.
* Specific executables such as msiexec.exe and appcmd.exe with certain arguments can be safely excluded if they are part of routine administrative tasks.
* Regularly review and update the exception list to ensure it aligns with current network management practices and tools.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further lateral movement by the adversary. This can be done by disabling network interfaces or using network segmentation tools.
* Terminate any suspicious processes identified as being executed via WMI on the affected host. Use task management tools or scripts to stop these processes.
* Conduct a thorough review of the affected host’s WMI logs and process execution history to identify any unauthorized changes or additional malicious activity.
* Reset credentials for any accounts that were used in the suspicious WMI activity, especially if they have administrative privileges, to prevent further unauthorized access.
* Apply patches and updates to the affected host and any other systems that may be vulnerable to similar exploitation methods, ensuring that all security updates are current.
* Enhance monitoring and logging for WMI activity across the network to detect and respond to similar threats more quickly in the future. This includes setting up alerts for unusual WMI usage patterns.
* If the threat is confirmed to be part of a larger attack, escalate the incident to the appropriate security team or authority for further investigation and potential legal action.


## Rule query [_rule_query_1210]

```js
sequence by host.id with maxspan = 2s

 /* Accepted Incoming RPC connection by Winmgmt service */

  [network where host.os.type == "windows" and process.name : "svchost.exe" and network.direction : ("incoming", "ingress") and
   source.ip != "127.0.0.1" and source.ip != "::1" and source.port >= 49152 and destination.port >= 49152
  ]

  /* Excluding Common FPs Nessus and SCCM */

  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "WmiPrvSE.exe" and
   not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
   not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
   not process.executable :
               ("?:\\Program Files\\HPWBEM\\Tools\\hpsum_swdiscovery.exe",
                "?:\\Windows\\CCM\\Ccm32BitLauncher.exe",
                "?:\\Windows\\System32\\wbem\\mofcomp.exe",
                "?:\\Windows\\Microsoft.NET\\Framework*\\csc.exe",
                "?:\\Windows\\System32\\powercfg.exe") and
   not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "REBOOT=ReallySuppress") and
   not (process.executable : "?:\\Windows\\System32\\inetsrv\\appcmd.exe" and process.args : "uninstall")
   ]
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



