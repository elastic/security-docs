---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-firsttime-seen-account-performing-dcsync.html
---

# FirstTime Seen Account Performing DCSync [prebuilt-rule-8-6-1-firsttime-seen-account-performing-dcsync]

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

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Active Directory

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3729]



## Rule query [_rule_query_4528]

```js
event.action : "Directory Service Access" and event.code : "4662" and
 winlog.event_data.Properties : (*DS-Replication-Get-Changes* or *DS-Replication-Get-Changes-All* or *DS-Replication-Get-Changes-In-Filtered-Set* or *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* or *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or *89e95b76-444d-4c62-991a-0facbeda640c*) and
 not winlog.event_data.SubjectUserName : (*$ or MSOL_*)
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



