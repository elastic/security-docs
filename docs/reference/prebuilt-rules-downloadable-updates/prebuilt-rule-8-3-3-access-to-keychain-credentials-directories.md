---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-access-to-keychain-credentials-directories.html
---

# Access to Keychain Credentials Directories [prebuilt-rule-8-3-3-access-to-keychain-credentials-directories]

Adversaries may collect the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes and certificates.

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

* [https://objective-see.com/blog/blog_0x25.html](https://objective-see.com/blog/blog_0x25.html)
* [https://securelist.com/calisto-trojan-for-macos/86543/](https://securelist.com/calisto-trojan-for-macos/86543/)

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

## Investigation guide [_investigation_guide_2961]



## Rule query [_rule_query_3409]

```js
process where event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Keychains/*",
      "/Library/Keychains/*",
      "/Network/Library/Keychains/*",
      "System.keychain",
      "login.keychain-db",
      "login.keychain"
    ) and
    not process.args : ("find-certificate",
                      "add-trusted-cert",
                      "set-keychain-settings",
                      "delete-certificate",
                      "/Users/*/Library/Keychains/openvpn.keychain-db",
                      "show-keychain-info",
                      "lock-keychain",
                      "set-key-partition-list",
                      "import",
                      "find-identity") and
    not process.parent.executable :
      (
        "/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect",
        "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon_enterprise.app/Contents/MacOS/wdavdaemon_enterprise",
        "/opt/jc/bin/jumpcloud-agent"
      ) and
    not process.executable : "/opt/jc/bin/jumpcloud-agent"
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



