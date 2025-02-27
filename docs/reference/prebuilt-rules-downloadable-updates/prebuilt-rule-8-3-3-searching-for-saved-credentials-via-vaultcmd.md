---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-searching-for-saved-credentials-via-vaultcmd.html
---

# Searching for Saved Credentials via VaultCmd [prebuilt-rule-8-3-3-searching-for-saved-credentials-via-vaultcmd]

Windows Credential Manager allows you to create, view, or delete saved credentials for signing into websites, connected applications, and networks. An adversary may abuse this to list or dump credentials stored in the Credential Manager for saved usernames and passwords. This may also be performed in preparation of lateral movement.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)
* [https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/](https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3029]



## Rule query [_rule_query_3526]

```js
process where event.type == "start" and
  (process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
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

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Windows Credential Manager
    * ID: T1555.004
    * Reference URL: [https://attack.mitre.org/techniques/T1555/004/](https://attack.mitre.org/techniques/T1555/004/)



