---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-dumping-of-keychain-content-via-security-command.html
---

# Dumping of Keychain Content via Security Command [prebuilt-rule-8-2-1-dumping-of-keychain-content-via-security-command]

Adversaries may dump the content of the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://ss64.com/osx/security.html](https://ss64.com/osx/security.html)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2037]



## Rule query [_rule_query_2327]

```js
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Keychain
    * ID: T1555.001
    * Reference URL: [https://attack.mitre.org/techniques/T1555/001/](https://attack.mitre.org/techniques/T1555/001/)



