---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-access-to-a-sensitive-ldap-attribute.html
---

# Access to a Sensitive LDAP Attribute [prebuilt-rule-8-6-1-access-to-a-sensitive-ldap-attribute]

Identify access to sensitive Active Directory object attributes that contains credentials and decryption keys such as unixUserPassword, ms-PKI-AccountCredentials and msPKI-CredentialRoamingTokens.

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

* [https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming](https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming)
* [https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx](https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Active Directory

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3768]

The 'Audit Directory Service Changes' logging policy must be configured for (Success, Failure).
Steps to implement the logging policy with Advanced Audit Configuration:

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

## Rule query [_rule_query_4598]

```js
any where event.action == "Directory Service Access" and event.code == "4662" and

  not winlog.event_data.SubjectUserSid : "S-1-5-18" and

  winlog.event_data.Properties : (
   /* unixUserPassword */
  "*612cb747-c0e8-4f92-9221-fdd5f15b550d*",

  /* ms-PKI-AccountCredentials */
  "*b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7*",

  /*  ms-PKI-DPAPIMasterKeys */
  "*b3f93023-9239-4f7c-b99c-6745d87adbc2*",

  /* msPKI-CredentialRoamingTokens */
  "*b7ff5a38-0818-42b0-8110-d3d154c97f24*"
  ) and

  /*
   Excluding noisy AccessMasks
   0x0 undefined and 0x100 Control Access
   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
   */
  not winlog.event_data.AccessMask in ("0x0", "0x100")
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



