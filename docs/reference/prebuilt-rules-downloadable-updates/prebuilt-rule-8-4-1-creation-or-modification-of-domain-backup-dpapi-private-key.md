---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-creation-or-modification-of-domain-backup-dpapi-private-key.html
---

# Creation or Modification of Domain Backup DPAPI private key [prebuilt-rule-8-4-1-creation-or-modification-of-domain-backup-dpapi-private-key]

Identifies the creation or modification of Domain Backup private keys. Adversaries may extract the Data Protection API (DPAPI) domain backup key from a Domain Controller (DC) to be able to decrypt any domain user master key file.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/](https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/)
* [https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Elastic Endgame

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2686]

## Triage and analysis

Domain DPAPI Backup keys are stored on domain controllers and can be dumped remotely with tools such as Mimikatz. The resulting .pvk private key can be used to decrypt ANY domain user masterkeys, which then can be used to decrypt any secrets protected by those keys.

## Rule query [_rule_query_3076]

```js
file where event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Private Keys
    * ID: T1552.004
    * Reference URL: [https://attack.mitre.org/techniques/T1552/004/](https://attack.mitre.org/techniques/T1552/004/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)



