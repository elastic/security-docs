---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-persistence-via-hidden-run-key-detected.html
---

# Persistence via Hidden Run Key Detected [prebuilt-rule-8-17-4-persistence-via-hidden-run-key-detected]

Identifies a persistence mechanism that utilizes the NtSetValueKey native API to create a hidden (null terminated) registry key. An adversary may use this method to hide from system utilities such as the Registry Editor (regedit).

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/outflanknl/SharpHide](https://github.com/outflanknl/SharpHide)
* [https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf](https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4945]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Hidden Run Key Detected**

The Windows Registry is a critical system database that stores configuration settings. Adversaries exploit it for persistence by creating hidden registry keys using native APIs, making them invisible to standard tools like regedit. The detection rule identifies changes in specific registry paths associated with startup programs, flagging null-terminated keys that suggest stealthy persistence tactics.

**Possible investigation steps**

* Review the specific registry path where the change was detected to determine if it matches any of the paths listed in the query, such as "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" or "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\".
* Check the timestamp of the registry change event to correlate it with other system activities or user actions that occurred around the same time.
* Investigate the process that made the registry change by examining process creation logs or using tools like Sysmon to identify the responsible process and its parent process.
* Analyze the content of the registry key value that was modified or created to determine if it points to a legitimate application or a potentially malicious executable.
* Cross-reference the detected registry change with known threat intelligence sources to identify if the key or value is associated with known malware or adversary techniques.
* Assess the affected system for additional indicators of compromise, such as unusual network connections, file modifications, or other persistence mechanisms.

**False positive analysis**

* Legitimate software installations or updates may create registry keys in the specified paths, leading to false positives. Users can monitor the installation process and temporarily disable the rule during known software updates to prevent unnecessary alerts.
* System administrators may intentionally configure startup programs for maintenance or monitoring purposes. Document these configurations and create exceptions in the detection rule to avoid flagging them as threats.
* Some security software may use similar techniques to ensure their components start with the system. Verify the legitimacy of such software and whitelist their registry changes to prevent false alarms.
* Custom scripts or automation tools used within an organization might modify registry keys for operational reasons. Identify these scripts and exclude their activities from the detection rule to reduce false positives.
* Regularly review and update the list of known safe applications and processes that interact with the registry paths in question, ensuring that the detection rule remains relevant and accurate.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Use a trusted tool to manually inspect and remove the hidden registry keys identified in the alert from the specified registry paths to eliminate the persistence mechanism.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes associated with the threat.
* Review recent user activity and system logs to identify any unauthorized access or changes made by the adversary, and reset credentials for any compromised accounts.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring on the affected system and similar endpoints to detect any recurrence of the threat, focusing on registry changes and process execution.
* Update and reinforce endpoint security configurations to prevent similar persistence techniques, such as enabling registry auditing and restricting access to critical registry paths.


## Setup [_setup_1557]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5900]

```js
/* Registry Path ends with backslash */
registry where host.os.type == "windows" and event.type == "change" and length(registry.data.strings) > 0 and
 registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



