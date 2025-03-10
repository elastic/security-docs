---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-firsttime-seen-account-performing-dcsync.html
---

# FirstTime Seen Account Performing DCSync [prebuilt-rule-8-17-4-firsttime-seen-account-performing-dcsync]

This rule identifies when a User Account starts the Active Directory Replication Process for the first time. Attackers can use the DCSync technique to get credential information of individual accounts or the entire domain, thus compromising the entire domain.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-180815210510.html](https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-180815210510.md)
* [https://threathunterplaybook.com/library/windows/active_directory_replication.html?highlight=dcsync#directory-replication-services-auditing](https://threathunterplaybook.com/library/windows/active_directory_replication.md?highlight=dcsync#directory-replication-services-auditing)
* [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_ad_replication_non_machine_account.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_ad_replication_non_machine_account.yml)
* [https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0027_windows_audit_directory_service_access.md](https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0027_windows_audit_directory_service_access.md)
* [https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync](https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync)
* [https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Privilege Escalation
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Resources: Investigation Guide
* Data Source: System

**Version**: 114

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4707]

**Triage and analysis**

**Investigating FirstTime Seen Account Performing DCSync**

Active Directory replication is the process by which the changes that originate on one domain controller are automatically transferred to other domain controllers that store the same data.

Active Directory data consists of objects that have properties, or attributes. Each object is an instance of an object class, and object classes and their respective attributes are defined in the Active Directory schema. Objects are defined by the values of their attributes, and changes to attribute values must be transferred from the domain controller on which they occur to every other domain controller that stores a replica of an affected object.

Adversaries can use the DCSync technique that uses Windows Domain Controller’s API to simulate the replication process from a remote domain controller, compromising major credential material such as the Kerberos krbtgt keys that are used legitimately for creating tickets, but also for forging tickets by attackers. This attack requires some extended privileges to succeed (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All), which are granted by default to members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups. Privileged accounts can be abused to grant controlled objects the right to DCsync/Replicate.

More details can be found on [Threat Hunter Playbook](https://threathunterplaybook.com/library/windows/active_directory_replication.md?highlight=dcsync#directory-replication-services-auditing) and [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync).

This rule monitors for when a Windows Event ID 4662 (Operation was performed on an Active Directory object) with the access mask 0x100 (Control Access) and properties that contain at least one of the following or their equivalent Schema-Id-GUID (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set) is seen in the environment for the first time in the last 15 days.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account and system owners and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Correlate security events 4662 and 4624 (Logon Type 3) by their Logon ID (`winlog.logon.id`) on the Domain Controller (DC) that received the replication request. This will tell you where the AD replication request came from, and if it came from another DC or not.
* Scope which credentials were compromised (for example, whether all accounts were replicated or specific ones).

**False positive analysis**

* Administrators may use custom accounts on Azure AD Connect; investigate if this is part of a new Azure AD account setup, and ensure it is properly secured. If the activity was expected and there is no other suspicious activity involving the host or user, the analyst can dismiss the alert.
* Although replicating Active Directory (AD) data to non-Domain Controllers is not a common practice and is generally not recommended from a security perspective, some software vendors may require it for their products to function correctly. Investigate if this is part of a new product setup, and ensure it is properly secured. If the activity was expected and there is no other suspicious activity involving the host or user, the analyst can dismiss the alert.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* If the entire domain or the `krbtgt` user was compromised:
* Activate your incident response plan for total Active Directory compromise which should include, but not be limited to, a password reset (twice) of the `krbtgt` user.
* Investigate how the attacker escalated privileges and identify systems they used to conduct lateral movement. Use this information to determine ways the attacker could regain access to the environment.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1506]

**Setup**

The *Audit Directory Service Access* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Access (Success,Failure)
```


## Rule query [_rule_query_5662]

```js
event.code:"4662" and winlog.event_data.Properties:(
                               *DS-Replication-Get-Changes* or *DS-Replication-Get-Changes-All* or
                               *DS-Replication-Get-Changes-In-Filtered-Set* or *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* or
                               *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or *89e95b76-444d-4c62-991a-0facbeda640c*) and
 not winlog.event_data.SubjectUserName:(*$ or MSOL_*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: DCSync
    * ID: T1003.006
    * Reference URL: [https://attack.mitre.org/techniques/T1003/006/](https://attack.mitre.org/techniques/T1003/006/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)



