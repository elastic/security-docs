---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-remote-desktop-shadowing-activity.html
---

# Potential Remote Desktop Shadowing Activity [prebuilt-rule-8-17-4-potential-remote-desktop-shadowing-activity]

Identifies the modification of the Remote Desktop Protocol (RDP) Shadow registry or the execution of processes indicative of an active RDP shadowing session. An adversary may abuse the RDP Shadowing feature to spy on or control other users active RDP sessions.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.registry-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://bitsadm.in/blog/spying-on-users-using-rdp-shadowing](https://bitsadm.in/blog/spying-on-users-using-rdp-shadowing)
* [https://swarm.ptsecurity.com/remote-desktop-services-shadowing/](https://swarm.ptsecurity.com/remote-desktop-services-shadowing/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4885]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Remote Desktop Shadowing Activity**

Remote Desktop Shadowing allows administrators to view or control active RDP sessions, aiding in support and troubleshooting. However, adversaries can exploit this feature to monitor or hijack user sessions without consent. The detection rule identifies suspicious modifications to RDP Shadow registry settings and the execution of specific processes linked to shadowing, signaling potential misuse.

**Possible investigation steps**

* Review the registry event details to confirm if there was a modification to the RDP Shadow registry path, specifically checking for changes in "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow".
* Investigate the process events to identify if "RdpSaUacHelper.exe" or "RdpSaProxy.exe" were started by "svchost.exe", which could indicate unauthorized shadowing activity.
* Check for any instances of "mstsc.exe" being executed with the "/shadow:*" argument, as this could signify an attempt to shadow an RDP session.
* Correlate the identified processes and registry changes with user activity logs to determine if the actions were authorized or expected as part of legitimate administrative tasks.
* Analyze network logs for any unusual remote connections or lateral movement patterns that coincide with the timing of the detected shadowing activity.
* Consult endpoint security solutions like Microsoft Defender for Endpoint or SentinelOne for additional context or alerts related to the same host or user account involved in the shadowing activity.

**False positive analysis**

* Legitimate administrative activities may trigger alerts when IT staff use RDP Shadowing for support. To manage this, create exceptions for known IT administrator accounts or specific IP addresses.
* Scheduled maintenance or automated scripts that modify RDP Shadow registry settings can be mistaken for malicious activity. Identify and exclude these processes or scripts from the detection rule.
* Security software or monitoring tools that interact with RDP sessions might mimic shadowing behavior. Verify these tools and whitelist their processes to prevent false alerts.
* Training sessions or remote support tools that use RDP Shadowing features can generate alerts. Document and exclude these activities by identifying their unique process names or arguments.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified in the alert, such as RdpSaUacHelper.exe, RdpSaProxy.exe, or mstsc.exe with shadowing arguments, to stop potential session hijacking.
* Revert any unauthorized changes to the RDP Shadow registry settings to their default or secure state to prevent further exploitation.
* Conduct a thorough review of user accounts and permissions on the affected system to ensure no unauthorized changes have been made, and reset passwords for any compromised accounts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for RDP activities across the network to detect and respond to similar threats more quickly in the future.
* Review and update RDP access policies and configurations to ensure they align with best practices, such as enforcing multi-factor authentication and limiting RDP access to only necessary users and systems.


## Rule query [_rule_query_5840]

```js
/* Identifies the modification of RDP Shadow registry or
  the execution of processes indicative of active shadow RDP session */

any where host.os.type == "windows" and
(
  (event.category == "registry" and
     registry.path : (
      "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow",
      "MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow"
    )
  ) or
  (event.category == "process" and event.type == "start" and
     (process.name : ("RdpSaUacHelper.exe", "RdpSaProxy.exe") and process.parent.name : "svchost.exe") or
     (?process.pe.original_file_name : "mstsc.exe" and process.args : "/shadow:*")
  )
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



