---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-port-monitor-or-print-processor-registration-abuse.html
---

# Potential Port Monitor or Print Processor Registration Abuse [prebuilt-rule-8-17-4-potential-port-monitor-or-print-processor-registration-abuse]

Identifies port monitor and print processor registry modifications. Adversaries may abuse port monitor and print processors to run malicious DLLs during system boot that will be executed as SYSTEM for privilege escalation and/or persistence, if permissions allow writing a fully-qualified pathname for that DLL.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4967]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Port Monitor or Print Processor Registration Abuse**

Port monitors and print processors are integral to Windows printing, managing data flow and processing print jobs. Adversaries exploit these by registering malicious DLLs, which execute with SYSTEM privileges at boot, enabling persistence and privilege escalation. The detection rule identifies registry changes in specific paths, focusing on non-SYSTEM user modifications, to flag potential abuse.

**Possible investigation steps**

* Review the registry path specified in the alert to confirm the presence of any unauthorized or suspicious DLLs in the paths: HKLM\SYSTEM*ControlSet*\Control\Print\Monitors\* and HKLM\SYSTEM*ControlSet*\Control\Print\Environments\Windows*\Print Processors\*.
* Identify the user account associated with the registry change by examining the user.id field, ensuring it is not the SYSTEM account (S-1-5-18), and determine if the account has a legitimate reason to modify these registry paths.
* Check the file properties and digital signatures of the DLLs found in the registry paths to verify their legitimacy and identify any anomalies or signs of tampering.
* Investigate the system’s event logs around the time of the registry change to gather additional context, such as other activities performed by the same user or related processes that might indicate malicious behavior.
* Conduct a threat intelligence search on the identified DLLs and any associated file hashes to determine if they are known to be associated with malicious activity or threat actors.
* Assess the system for any signs of privilege escalation or persistence mechanisms that may have been established as a result of the registry modification, such as new services or scheduled tasks.

**False positive analysis**

* Legitimate software installations or updates may modify print processor or port monitor registry paths. Users should verify if recent installations or updates coincide with the detected changes.
* System administrators performing maintenance or configuration changes might trigger alerts. Ensure that such activities are documented and cross-referenced with the alert timestamps.
* Some third-party printing solutions may register their own DLLs in these registry paths. Identify and whitelist these known applications to prevent unnecessary alerts.
* Automated scripts or management tools that modify printer settings could cause false positives. Review and adjust these tools to ensure they operate under expected user accounts or exclude their known behaviors.
* Regularly review and update the exclusion list to include any new benign applications or processes that interact with the monitored registry paths.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes associated with the malicious DLLs identified in the registry paths to halt their execution.
* Remove the unauthorized DLL entries from the registry paths: HKLM\SYSTEM*ControlSet*\Control\Print\Monitors\* and HKLM\SYSTEM*ControlSet*\Control\Print\Environments\Windows*\Print Processors\* to eliminate persistence mechanisms.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and reset credentials for any accounts that may have been compromised, especially those with elevated privileges, to prevent unauthorized access.
* Implement application whitelisting to prevent unauthorized DLLs from executing, focusing on the paths identified in the alert.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected, ensuring comprehensive threat containment and eradication.


## Rule query [_rule_query_5922]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*"
  ) and registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Port Monitors
    * ID: T1547.010
    * Reference URL: [https://attack.mitre.org/techniques/T1547/010/](https://attack.mitre.org/techniques/T1547/010/)

* Sub-technique:

    * Name: Print Processors
    * ID: T1547.012
    * Reference URL: [https://attack.mitre.org/techniques/T1547/012/](https://attack.mitre.org/techniques/T1547/012/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Port Monitors
    * ID: T1547.010
    * Reference URL: [https://attack.mitre.org/techniques/T1547/010/](https://attack.mitre.org/techniques/T1547/010/)

* Sub-technique:

    * Name: Print Processors
    * ID: T1547.012
    * Reference URL: [https://attack.mitre.org/techniques/T1547/012/](https://attack.mitre.org/techniques/T1547/012/)



