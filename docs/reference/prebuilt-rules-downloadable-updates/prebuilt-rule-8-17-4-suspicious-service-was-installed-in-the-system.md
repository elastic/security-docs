---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-service-was-installed-in-the-system.html
---

# Suspicious Service was Installed in the System [prebuilt-rule-8-17-4-suspicious-service-was-installed-in-the-system]

Identifies the creation of a new Windows service with suspicious Service command values. Windows services typically run as SYSTEM and can be used for privilege escalation and persistence.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

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
* Tactic: Persistence
* Resources: Investigation Guide
* Data Source: System

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4931]

**Triage and analysis**

**Investigating Suspicious Service was Installed in the System**

Attackers may create new services to execute system shells and other command execution utilities to elevate their privileges from administrator to SYSTEM. They can also configure services to execute these utilities with persistence payloads.

This rule looks for suspicious services being created with suspicious traits compatible with the above behavior.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify how the service was created or modified. Look for registry changes events or Windows events related to service activities (for example, 4697 and/or 7045).
* Examine the created and existent services, the executables or drivers referenced, and command line arguments for suspicious entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* !{osquery{"label":"Osquery - Retrieve All Non-Microsoft Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE NOT (provider == \"Microsoft\" AND signed == \"1\")\n"}}
* !{osquery{"label":"Osquery - Retrieve All Unsigned Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE signed == \"0\"\n"}}
* Retrieve the referenced files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.

**False positive analysis**

* Certain services such as PSEXECSVC may happen legitimately. The security team should address any potential benign true positive (B-TP) by excluding the relevant FP by pattern.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Delete the service.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_5886]

```js
any where
  (event.code : "4697" and
   (winlog.event_data.ServiceFileName :
           ("*COMSPEC*", "*\\127.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*",
            "*echo*", "*RemComSvc*", "*.bat*", "*.cmd*", "*certutil*", "*vssadmin*", "*certmgr*", "*bitsadmin*",
            "*\\Users\\*", "*\\Windows\\Temp\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*", "*\\Windows\\Debug\\*",
            "*regsvr32*", "*msbuild*") or
   winlog.event_data.ServiceFileName regex~ """%systemroot%\\[a-z0-9]+\.exe""")) or

  (event.code : "7045" and
   winlog.event_data.ImagePath : (
       "*COMSPEC*", "*\\127.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*",
       "*echo*", "*RemComSvc*", "*.bat*", "*.cmd*", "*certutil*", "*vssadmin*", "*certmgr*", "*bitsadmin*",
       "*\\Users\\*", "*\\Windows\\Temp\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*", "*\\Windows\\Debug\\*",
       "*regsvr32*", "*msbuild*"))
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



