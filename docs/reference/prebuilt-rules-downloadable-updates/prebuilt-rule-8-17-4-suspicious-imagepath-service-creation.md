---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-imagepath-service-creation.html
---

# Suspicious ImagePath Service Creation [prebuilt-rule-8-17-4-suspicious-imagepath-service-creation]

Identifies the creation of a suspicious ImagePath value. This could be an indication of an adversary attempting to stealthily persist or escalate privileges through abnormal service creation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
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

## Investigation guide [_investigation_guide_4938]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious ImagePath Service Creation**

Windows services are crucial for running background processes. Adversaries exploit this by creating or modifying services with malicious ImagePath values to gain persistence or escalate privileges. The detection rule monitors registry changes to ImagePath entries, flagging unusual patterns like command shells or named pipes, which are often used in stealthy attacks. This helps identify and mitigate potential threats early.

**Possible investigation steps**

* Review the registry event logs to identify the specific ImagePath value that triggered the alert, focusing on entries with command shells or named pipes, such as those containing "%COMSPEC%**" or "**\\.\\pipe\\*".
* Investigate the associated service name and description in the registry path "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath" to determine if it is a legitimate service or potentially malicious.
* Check the creation or modification timestamp of the suspicious ImagePath entry to correlate with other system events or user activities around the same time.
* Analyze the parent process and user account responsible for the registry change to assess if it aligns with expected behavior or if it indicates unauthorized access.
* Search for related network activity or connections, especially those involving named pipes, to identify any lateral movement or data exfiltration attempts.
* Cross-reference the alert with threat intelligence sources to determine if the ImagePath value or associated service is linked to known malware or adversary techniques.

**False positive analysis**

* Legitimate software updates or installations may modify ImagePath values, triggering alerts. Users can create exceptions for known software update processes to reduce noise.
* System administrators might intentionally change service configurations for maintenance or optimization. Document and exclude these planned changes to prevent false positives.
* Some enterprise applications use named pipes for inter-process communication, which could be flagged. Identify and whitelist these applications to avoid unnecessary alerts.
* Security tools or scripts that automate service management might alter ImagePath values. Ensure these tools are recognized and excluded from monitoring to minimize false alerts.
* Regularly review and update the list of exceptions to ensure they align with current organizational practices and software environments.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes associated with the identified ImagePath values, such as those involving command shells or named pipes.
* Remove or disable the malicious service by reverting the ImagePath registry entry to its legitimate state or deleting the service if it is not required.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional threats or malware.
* Review and restore any modified system files or configurations to their original state to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for similar registry changes and suspicious service creations to detect and respond to future threats promptly.


## Rule query [_rule_query_5893]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "ImagePath" and
  registry.path : (
    "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath"
    ) and
  /* add suspicious registry ImagePath values here */
  registry.data.strings : ("%COMSPEC%*", "*\\.\\pipe\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



