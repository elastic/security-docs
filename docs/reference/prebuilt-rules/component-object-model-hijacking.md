---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/component-object-model-hijacking.html
---

# Component Object Model Hijacking [component-object-model-hijacking]

Identifies Component Object Model (COM) hijacking via registry modification. Adversaries may establish persistence by executing malicious content triggered by hijacked references to COM objects.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Tactic: Privilege Escalation
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend

**Version**: 114

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_228]

**Triage and analysis**

**Investigating Component Object Model Hijacking**

Adversaries can insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means of persistence.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* Retrieve the file referenced in the registry and determine if it is malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* File and registry access, modification, and creation activities.
* Service creation and launch activities.
* Scheduled task creation.
* Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
* Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* Some Microsoft executables will reference the LocalServer32 registry key value for the location of external COM objects.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_151]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_236]

```js
registry where host.os.type == "windows" and event.type == "change" and
  /* not necessary but good for filtering privileged installations */
  user.domain != "NT AUTHORITY" and process.executable != null and
  (
    (
      registry.path : "HK*\\InprocServer32\\" and
      registry.data.strings: ("scrobj.dll", "?:\\*\\scrobj.dll") and
      not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*"
    ) or

    (
      registry.path : "HKLM\\*\\InProcServer32\\*" and
        registry.data.strings : ("*\\Users\\*", "*\\ProgramData\\*")
    ) or

    /* in general COM Registry changes on Users Hive is less noisy and worth alerting */
    (
      registry.path : (
        "HKEY_USERS\\*\\InprocServer32\\",
        "HKEY_USERS\\*\\LocalServer32\\",
        "HKEY_USERS\\*\\DelegateExecute",
        "HKEY_USERS\\*\\TreatAs\\",
        "HKEY_USERS\\*\\ScriptletURL*"
      )
    )
  ) and

      not  (
            process.code_signature.trusted == true and
            process.code_signature.subject_name in
                         ("Island Technology Inc.", "Google LLC", "Grammarly, Inc.", "Dropbox, Inc", "REFINITIV US LLC", "HP Inc.",
                          "Citrix Systems, Inc.", "Adobe Inc.", "Veeam Software Group GmbH", "Zhuhai Kingsoft Office Software Co., Ltd.",
                          "Oracle America, Inc.")
        ) and

  /* excludes Microsoft signed noisy processes */
  not
  (
    process.name : ("OneDrive.exe", "OneDriveSetup.exe", "FileSyncConfig.exe", "Teams.exe", "MicrosoftEdgeUpdate.exe", "msrdcw.exe", "MicrosoftEdgeUpdateComRegisterShell64.exe") and
    process.code_signature.trusted == true and process.code_signature.subject_name in ("Microsoft Windows", "Microsoft Corporation")
  ) and

  not process.executable :
                  ("?:\\Program Files (x86)\\*.exe",
                   "?:\\Program Files\\*.exe",
                   "?:\\Windows\\System32\\svchost.exe",
                   "?:\\Windows\\System32\\msiexec.exe",
                   "?:\\Windows\\SysWOW64\\regsvr32.exe",
                   "?:\\Windows\\System32\\regsvr32.exe",
                   "?:\\Windows\\System32\\DriverStore\\FileRepository\\*.exe",
                   "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Component Object Model Hijacking
    * ID: T1546.015
    * Reference URL: [https://attack.mitre.org/techniques/T1546/015/](https://attack.mitre.org/techniques/T1546/015/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Component Object Model Hijacking
    * ID: T1546.015
    * Reference URL: [https://attack.mitre.org/techniques/T1546/015/](https://attack.mitre.org/techniques/T1546/015/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



