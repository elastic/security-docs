---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-enumeration-of-privileged-local-groups-membership.html
---

# Enumeration of Privileged Local Groups Membership [prebuilt-rule-8-17-4-enumeration-of-privileged-local-groups-membership]

Identifies instances of an unusual process enumerating built-in Windows privileged local groups membership like Administrators or Remote Desktop users.

**Rule type**: new_terms

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
* Tactic: Discovery
* Resources: Investigation Guide
* Data Source: System

**Version**: 416

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4828]

**Triage and analysis**

**Investigating Enumeration of Privileged Local Groups Membership**

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps. This can happen by running commands to enumerate network resources, users, connections, files, and installed security software.

This rule looks for the enumeration of privileged local groups' membership by suspicious processes, and excludes known legitimate utilities and programs installed. Attackers can use this information to decide the next steps of the attack, such as mapping targets for credential compromise and other post-exploitation activities.

[TBC: QUOTE]
**Possible investigation steps**

* Identify the process, host and user involved on the event.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the process executable using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target host after the registry modification.

**False positive analysis**

* Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.
* If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a combination of user and command line conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1542]

**Setup**

The *Audit Security Group Management* audit policy must be configured (Success). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Management >
Audit Security Group Management (Success)
```

Microsoft introduced the [event used](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799) in this detection rule on Windows 10 and Windows Server 2016 or later operating systems.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5783]

```js
host.os.type:windows and event.category:iam and event.action:user-member-enumerated and
  (
    group.name:(*Admin* or "RemoteDesktopUsers") or
    winlog.event_data.TargetSid:("S-1-5-32-544" or "S-1-5-32-555")
  ) and
  not (
    winlog.event_data.SubjectUserName: *$ or
    winlog.event_data.SubjectUserSid: ("S-1-5-19" or "S-1-5-20") or
    winlog.event_data.CallerProcessName:("-" or
                                       C\:\\Windows\\System32\\VSSVC.exe or
                                       C\:\\Windows\\System32\\SearchIndexer.exe or
                                       C\:\\Windows\\System32\\CompatTelRunner.exe or
                                       C\:\\Windows\\System32\\oobe\\msoobe.exe or
                                       C\:\\Windows\\System32\\net1.exe or
                                       C\:\\Windows\\System32\\svchost.exe or
                                       C\:\\Windows\\System32\\Netplwiz.exe or
                                       C\:\\Windows\\System32\\msiexec.exe or
                                       C\:\\Windows\\System32\\CloudExperienceHostBroker.exe or
                                       C\:\\Windows\\System32\\RuntimeBroker.exe or
                                       C\:\\Windows\\System32\\wbem\\WmiPrvSE.exe or
                                       C\:\\Windows\\System32\\SrTasks.exe or
                                       C\:\\Windows\\System32\\diskshadow.exe or
                                       C\:\\Windows\\System32\\dfsrs.exe or
                                       C\:\\Windows\\System32\\vssadmin.exe or
                                       C\:\\Windows\\System32\\dllhost.exe or
                                       C\:\\Windows\\System32\\mmc.exe or
                                       C\:\\Windows\\System32\\SettingSyncHost.exe or
                                       C\:\\Windows\\System32\\inetsrv\\w3wp.exe or
                                       C\:\\Windows\\System32\\wsmprovhost.exe or
                                       C\:\\Windows\\System32\\mstsc.exe or
                                       C\:\\Windows\\System32\\esentutl.exe or
                                       C\:\\Windows\\System32\\RecoveryDrive.exe or
                                       C\:\\Windows\\System32\\SystemPropertiesComputerName.exe or
                                       C\:\\Windows\\SysWOW64\\msiexec.exe or
                                       C\:\\Windows\\System32\\taskhostw.exe or
                                       C\:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe or
                                       C\:\\Windows\\Temp\\rubrik_vmware*\\snaptool.exe or
                                       C\:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe or
                                       C\:\\WindowsAzure\\*WaAppAgent.exe or
                                       C\:\\$WINDOWS.~BT\\Sources\\*.exe
                                      )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)



