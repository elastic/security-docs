---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-systemkey-access-via-command-line.html
---

# SystemKey Access via Command Line [prebuilt-rule-8-4-2-systemkey-access-via-command-line]

Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos. Adversaries may collect the keychain storage data from a system to acquire credentials.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/AlessandroZ/LaZagne/blob/master/Mac/lazagne/softwares/system/chainbreaker.py](https://github.com/AlessandroZ/LaZagne/blob/master/Mac/lazagne/softwares/system/chainbreaker.py)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3907]

```js
event.category:process and event.type:(start or process_started) and
  process.args:("/private/var/db/SystemKey" or "/var/db/SystemKey")
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



