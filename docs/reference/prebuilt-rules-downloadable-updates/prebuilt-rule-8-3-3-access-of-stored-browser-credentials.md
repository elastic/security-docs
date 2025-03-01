---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-access-of-stored-browser-credentials.html
---

# Access of Stored Browser Credentials [prebuilt-rule-8-3-3-access-of-stored-browser-credentials]

Identifies the execution of a process with arguments pointing to known browser files that store passwords and cookies. Adversaries may acquire credentials from web browsers by reading files specific to the target browser.

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

## Investigation guide [_investigation_guide_2960]



## Rule query [_rule_query_3408]

```js
process where event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Application Support/Google/Chrome/Default/Login Data",
      "/Users/*/Library/Application Support/Google/Chrome/Default/Cookies",
      "/Users/*/Library/Application Support/Google/Chrome/Profile*/Cookies",
      "/Users/*/Library/Cookies*",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/key*.db",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/logins.json",
      "Login Data",
      "Cookies.binarycookies",
      "key4.db",
      "key3.db",
      "logins.json",
      "cookies.sqlite"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Web Session Cookie
    * ID: T1539
    * Reference URL: [https://attack.mitre.org/techniques/T1539/](https://attack.mitre.org/techniques/T1539/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Credentials from Web Browsers
    * ID: T1555.003
    * Reference URL: [https://attack.mitre.org/techniques/T1555/003/](https://attack.mitre.org/techniques/T1555/003/)



