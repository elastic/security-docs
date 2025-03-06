---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-keychain-password-retrieval-via-command-line.html
---

# Keychain Password Retrieval via Command Line [prebuilt-rule-8-2-1-keychain-password-retrieval-via-command-line]

Adversaries may collect keychain storage data from a system to in order to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos.

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

* [https://www.netmeister.org/blog/keychain-passwords.html](https://www.netmeister.org/blog/keychain-passwords.html)
* [https://github.com/priyankchheda/chrome_password_grabber/blob/master/chrome.py](https://github.com/priyankchheda/chrome_password_grabber/blob/master/chrome.py)
* [https://ss64.com/osx/security.html](https://ss64.com/osx/security.html)
* [https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/](https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2038]



## Rule query [_rule_query_2328]

```js
process where event.type == "start" and
 process.name : "security" and process.args : "-wa" and process.args : ("find-generic-password", "find-internet-password") and
 process.args : ("Chrome*", "Chromium", "Opera", "Safari*", "Brave", "Microsoft Edge", "Edge", "Firefox*") and
 not process.parent.executable : "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
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

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Credentials from Web Browsers
    * ID: T1555.003
    * Reference URL: [https://attack.mitre.org/techniques/T1555/003/](https://attack.mitre.org/techniques/T1555/003/)



