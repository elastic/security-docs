---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-multiple-vault-web-credentials-read.html
---

# Multiple Vault Web Credentials Read [prebuilt-rule-8-4-2-multiple-vault-web-credentials-read]

Windows Credential Manager allows you to create, view, or delete saved credentials for signing into websites, connected applications, and networks. An adversary may abuse this to list or dump credentials stored in the Credential Manager for saved usernames and passwords. This may also be performed in preparation of lateral movement.

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

* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5382](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5382)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3374]



## Rule query [_rule_query_4015]

```js
sequence by winlog.computer_name, winlog.process.pid with maxspan=1s

 /* 2 consecutive vault reads from same pid for web creds */

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" or winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7"]

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" or winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7"]
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



