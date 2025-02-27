---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-modification-of-the-mspkiaccountcredentials.html
---

# Modification of the msPKIAccountCredentials [prebuilt-rule-8-4-3-modification-of-the-mspkiaccountcredentials]

Identify the modification of the msPKIAccountCredentials attribute in an Active Directory User Object. Attackers can abuse the credentials roaming feature to overwrite an arbitrary file for privilege escalation. ms-PKI-AccountCredentials contains binary large objects (BLOBs) of encrypted credential objects from the credential manager store, private keys, certificates, and certificate requests.

**Rule type**: query

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

* [https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming](https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming)
* [https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx](https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Active Directory
* Privilege Escalation

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3645]



## Rule query [_rule_query_4389]

```js
event.action:"Directory Service Changes" and event.code:"5136" and
 winlog.event_data.AttributeLDAPDisplayName:"msPKIAccountCredentials" and winlog.event_data.OperationType:"%%14674" and
 not winlog.event_data.SubjectUserSid : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



