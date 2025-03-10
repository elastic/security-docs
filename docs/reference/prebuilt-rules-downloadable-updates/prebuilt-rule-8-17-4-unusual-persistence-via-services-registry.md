---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-persistence-via-services-registry.html
---

# Unusual Persistence via Services Registry [prebuilt-rule-8-17-4-unusual-persistence-via-services-registry]

Identifies processes modifying the services registry key directly, instead of through the expected Windows APIs. This could be an indication of an adversary attempting to stealthily persist through abnormal service creation or modification of an existing service.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

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

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4932]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Persistence via Services Registry**

Windows services are crucial for running background processes. Adversaries may exploit this by directly altering service registry keys to maintain persistence, bypassing standard APIs. The detection rule identifies such anomalies by monitoring changes to specific registry paths and filtering out legitimate processes, thus highlighting potential unauthorized service modifications indicative of malicious activity.

**Possible investigation steps**

* Review the specific registry paths and values that triggered the alert, focusing on "ServiceDLL" and "ImagePath" within the specified registry paths to identify any unauthorized or suspicious modifications.
* Examine the process responsible for the registry change, paying attention to the process name and executable path, to determine if it is a known legitimate process or potentially malicious.
* Cross-reference the process executable path against the list of known legitimate paths excluded in the query to ensure it is not a false positive.
* Investigate the historical behavior of the process and any associated files or network activity to identify patterns indicative of malicious intent or persistence mechanisms.
* Check for any recent changes or anomalies in the system’s service configurations that could correlate with the registry modifications, indicating potential unauthorized service creation or alteration.
* Consult threat intelligence sources or databases to determine if the process or registry changes are associated with known malware or adversary techniques.

**False positive analysis**

* Legitimate software installations or updates may modify service registry keys directly. Users can create exceptions for known software update processes by excluding their executables from the detection rule.
* System maintenance tools like Process Explorer may trigger false positives when they interact with service registry keys. Exclude these tools by adding their process names and paths to the exception list.
* Drivers installed by trusted hardware peripherals might alter service registry keys. Users should identify and exclude these driver paths if they are known to be safe and frequently updated.
* Custom enterprise applications that require direct registry modifications for service management can be excluded by specifying their executable paths in the rule exceptions.
* Regular system processes such as svchost.exe or services.exe are already excluded, but ensure any custom scripts or automation tools that mimic these processes are also accounted for in the exceptions.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified in the alert that are not part of legitimate applications or services.
* Restore the modified registry keys to their original state using a known good backup or by manually correcting the entries to ensure the integrity of the service configurations.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious software or artifacts.
* Review and update endpoint protection policies to ensure that similar unauthorized registry modifications are detected and blocked in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Document the incident details, including the steps taken for containment and remediation, to enhance future response efforts and update threat intelligence databases.


## Rule query [_rule_query_5887]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : ("ServiceDLL", "ImagePath") and
  registry.path : (
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
      "MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath"
  ) and not registry.data.strings : (
      "?:\\windows\\system32\\Drivers\\*.sys",
      "\\SystemRoot\\System32\\drivers\\*.sys",
      "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
      "\\??\\?:\\Windows\\syswow64\\*.sys",
      "system32\\DRIVERS\\USBSTOR") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\svchost.exe",
      "?:\\Windows\\winsxs\\*\\TiWorker.exe",
      "?:\\Windows\\System32\\drvinst.exe",
      "?:\\Windows\\System32\\services.exe",
      "?:\\Windows\\System32\\msiexec.exe",
      "?:\\Windows\\System32\\regsvr32.exe",
      "?:\\Windows\\System32\\WaaSMedicAgent.exe"
  )
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



