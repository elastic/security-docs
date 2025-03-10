---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/scheduled-task-execution-at-scale-via-gpo.html
---

# Scheduled Task Execution at Scale via GPO [scheduled-task-execution-at-scale-via-gpo]

Detects the modification of Group Policy Object attributes to execute a scheduled task in the objects controlled by the GPO.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md)
* [https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md](https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md)
* [https://labs.f-secure.com/tools/sharpgpoabuse](https://labs.f-secure.com/tools/sharpgpoabuse)
* [https://twitter.com/menasec1/status/1106899890377052160](https://twitter.com/menasec1/status/1106899890377052160)
* [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_gpo_scheduledtasks.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_gpo_scheduledtasks.yml)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Lateral Movement
* Data Source: Active Directory
* Resources: Investigation Guide
* Use Case: Active Directory Monitoring
* Data Source: System

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_904]

**Triage and analysis**

**Investigating Scheduled Task Execution at Scale via GPO**

Group Policy Objects (GPOs) can be used by attackers to execute scheduled tasks at scale to compromise objects controlled by a given GPO. This is done by changing the contents of the `<GPOPath>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` file.

**Possible investigation steps**

* This attack abuses a legitimate mechanism of Active Directory, so it is important to determine whether the activity is legitimate and the administrator is authorized to perform this operation.
* Retrieve the contents of the `ScheduledTasks.xml` file, and check the `<Command>` and `<Arguments>` XML tags for any potentially malicious commands or binaries.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Scope which objects may be compromised by retrieving information about which objects are controlled by the GPO.

**False positive analysis**

* Verify if the execution is allowed and done under change management, and if the execution is legitimate.

**Related rules**

* Group Policy Abuse for Privilege Addition - b9554892-5e0e-424b-83a0-5aef95aa43bf
* Startup/Logon Script added to Group Policy Object - 16fac1a1-21ee-4ca6-b720-458e3855d046

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* The investigation and containment must be performed in every computer controlled by the GPO, where necessary.
* Remove the script from the GPO.
* Check if other GPOs have suspicious scheduled tasks attached.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_570]

**Setup**

The *Audit Detailed File Share* audit policy must be configured (Success Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Object Access >
Audit Detailed File Share (Success,Failure)
```

The *Audit Directory Service Changes* audit policy must be configured (Success Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```


## Rule query [_rule_query_960]

```js
any where host.os.type == "windows" and event.code in ("5136", "5145") and
(
  (
    winlog.event_data.AttributeLDAPDisplayName : (
      "gPCMachineExtensionNames",
      "gPCUserExtensionNames"
    ) and
    winlog.event_data.AttributeValue : "*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*" and
    winlog.event_data.AttributeValue : "*AADCED64-746C-4633-A97C-D61349046527*"
  ) or
  (
    winlog.event_data.ShareName : "\\\\*\\SYSVOL" and
    winlog.event_data.RelativeTargetName : "*ScheduledTasks.xml" and
    winlog.event_data.AccessList:"*%%4417*"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)

* Technique:

    * Name: Domain or Tenant Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Group Policy Modification
    * ID: T1484.001
    * Reference URL: [https://attack.mitre.org/techniques/T1484/001/](https://attack.mitre.org/techniques/T1484/001/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Lateral Tool Transfer
    * ID: T1570
    * Reference URL: [https://attack.mitre.org/techniques/T1570/](https://attack.mitre.org/techniques/T1570/)



