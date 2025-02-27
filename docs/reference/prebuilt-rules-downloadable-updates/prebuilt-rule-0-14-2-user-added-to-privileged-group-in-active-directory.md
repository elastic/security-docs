---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-user-added-to-privileged-group-in-active-directory.html
---

# User Added to Privileged Group in Active Directory [prebuilt-rule-0-14-2-user-added-to-privileged-group-in-active-directory]

Identifies a user being added to a privileged group in Active Directory. Privileged accounts and groups in Active Directory are those to which powerful rights, privileges, and permissions are granted that allow them to perform nearly any action in Active Directory and on domain-joined systems.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b—​privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b—​privileged-accounts-and-groups-in-active-directory)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 3

**Rule authors**:

* Elastic
* Skoetting

**Rule license**: Elastic License v2

## Rule query [_rule_query_1479]

```js
iam where event.action == "added-member-to-group" and
  group.name : ("Admin*",
                "Local Administrators",
                "Domain Admins",
                "Enterprise Admins",
                "Backup Admins",
                "Schema Admins",
                "DnsAdmins",
                "Exchange Organization Administrators")
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



