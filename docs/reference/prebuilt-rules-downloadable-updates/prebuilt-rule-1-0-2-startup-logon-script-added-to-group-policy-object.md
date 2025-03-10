---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-startup-logon-script-added-to-group-policy-object.html
---

# Startup/Logon Script added to Group Policy Object [prebuilt-rule-1-0-2-startup-logon-script-added-to-group-policy-object]

Detects the modification of Group Policy Objects (GPO) to add a startup/logon script to users or computer objects.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md)
* [https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md](https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md)
* [https://labs.f-secure.com/tools/sharpgpoabuse](https://labs.f-secure.com/tools/sharpgpoabuse)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation
* Active Directory

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1658]

## Triage and analysis

## Investigating Scheduled Task Execution at Scale via GPO

Group Policy Objects (GPOs) can be used by attackers to instruct arbitrarily large groups of
clients to execute specified commands at startup, logon, shutdown, and logoff. This is done by creating or modifying the
`scripts.ini` or `psscripts.ini` files. The scripts are stored in the following path: `<GPOPath>\Machine\Scripts\`,
`<GPOPath>\User\Scripts\`

### Possible investigation steps

- This attack abuses a legitimate mechanism of the Active Directory, so it is important to determine whether the
activity is legitimate and the administrator is authorized to perform this operation.
- Retrieve the contents of the script file, and check for any potentially malicious commands and binaries.
- Investigate other alerts related to the user/host in the last 48 hours.
- Scope which objects have been affected.

## False positive analysis

- Verify if the execution is legitimately authorized and executed under a change management process.

## Related rules

- Group Policy Abuse for Privilege Addition - b9554892-5e0e-424b-83a0-5aef95aa43bf
- Scheduled Task Execution at Scale via GPO - 15a8ba77-1c13-4274-88fe-6bd14133861e

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- The investigation and containment must be performed in every computer controlled by the GPO, where necessary.
- Remove the script from the GPO.
- Check if other GPOs have suspicious scripts attached.

## Config

The 'Audit Detailed File Share' audit policy must be configured (Success Failure).
Steps to implement the logging policy with with Advanced Audit Configuration:

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

The 'Audit Directory Service Changes' audit policy must be configured (Success Failure).
Steps to implement the logging policy with with Advanced Audit Configuration:

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

## Rule query [_rule_query_1921]

```js
(
 event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:(gPCMachineExtensionNames or gPCUserExtensionNames) and
   winlog.event_data.AttributeValue:(*42B5FAAE-6536-11D2-AE5A-0000F87571E3* and
                                      (*40B66650-4972-11D1-A7CA-0000F87571E3* or *40B6664F-4972-11D1-A7CA-0000F87571E3*))
)
or
(
 event.code:5145 and winlog.event_data.ShareName:\\\\*\\SYSVOL and
   winlog.event_data.RelativeTargetName:(*\\scripts.ini or *\\psscripts.ini) and
   (message:WriteData or winlog.event_data.AccessList:*%%4417*)
)
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

* Technique:

    * Name: Domain Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Group Policy Modification
    * ID: T1484.001
    * Reference URL: [https://attack.mitre.org/techniques/T1484/001/](https://attack.mitre.org/techniques/T1484/001/)



