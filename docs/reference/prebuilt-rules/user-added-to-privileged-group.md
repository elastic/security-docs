---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/user-added-to-privileged-group.html
---

# User Added to Privileged Group [user-added-to-privileged-group]

Identifies a user being added to a privileged group in Active Directory. Privileged accounts and groups in Active Directory are those to which powerful rights, privileges, and permissions are granted that allow them to perform nearly any action in Active Directory and on domain-joined systems.

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

**References**:

* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b—​privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b—​privileged-accounts-and-groups-in-active-directory)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Resources: Investigation Guide
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Data Source: System

**Version**: 211

**Rule authors**:

* Elastic
* Skoetting

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1174]

**Triage and analysis**

**Investigating User Added to Privileged Group in Active Directory**

Privileged accounts and groups in Active Directory are those to which powerful rights, privileges, and permissions are granted that allow them to perform nearly any action in Active Directory and on domain-joined systems.

Attackers can add users to privileged groups to maintain a level of access if their other privileged accounts are uncovered by the security team. This allows them to keep operating after the security team discovers abused accounts.

This rule monitors events related to a user being added to a privileged group.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should manage members of this group.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* This attack abuses a legitimate Active Directory mechanism, so it is important to determine whether the activity is legitimate, if the administrator is authorized to perform this operation, and if there is a need to grant the account this level of privilege.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* If the admin is not aware of the operation, activate your Active Directory incident response plan.
* If the user does not need the administrator privileges, remove the account from the privileged group.
* Review the privileges of the administrator account that performed the action.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_745]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1197]

```js
iam where winlog.api == "wineventlog" and event.action == "added-member-to-group" and
(
    (
        group.name : (
            "Admin*",
            "Local Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Backup Admins",
            "Schema Admins",
            "DnsAdmins",
            "Exchange Organization Administrators",
            "Print Operators",
            "Server Operators",
            "Account Operators"
        )
    ) or
    (
        group.id : (
            "S-1-5-32-544",
            "S-1-5-21-*-544",
            "S-1-5-21-*-512",
            "S-1-5-21-*-519",
            "S-1-5-21-*-551",
            "S-1-5-21-*-518",
            "S-1-5-21-*-1101",
            "S-1-5-21-*-1102",
            "S-1-5-21-*-550",
            "S-1-5-21-*-549",
            "S-1-5-21-*-548"
        )
    )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



