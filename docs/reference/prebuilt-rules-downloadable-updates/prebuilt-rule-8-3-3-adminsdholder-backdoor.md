---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-adminsdholder-backdoor.html
---

# AdminSDHolder Backdoor [prebuilt-rule-8-3-3-adminsdholder-backdoor]

Detects modifications in the AdminSDHolder object. Attackers can abuse the SDProp process to implement a persistent backdoor in Active Directory. SDProp compares the permissions on protected objects with those defined on the AdminSDHolder object. If the permissions on any of the protected accounts and groups do not match, the permissions on the protected accounts and groups are reset to match those of the domain’s AdminSDHolder object, regaining their Administrative Privileges.

**Rule type**: query

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

* [https://adsecurity.org/?p=1906](https://adsecurity.org/?p=1906)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c—​protected-accounts-and-groups-in-active-directory#adminsdholder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c—​protected-accounts-and-groups-in-active-directory#adminsdholder)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Active Directory

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3693]

```js
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



