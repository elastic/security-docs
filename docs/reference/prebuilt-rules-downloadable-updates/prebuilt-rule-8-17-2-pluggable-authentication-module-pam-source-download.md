---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-pluggable-authentication-module-pam-source-download.html
---

# Pluggable Authentication Module (PAM) Source Download [prebuilt-rule-8-17-2-pluggable-authentication-module-pam-source-download]

This rule detects the usage of `curl` or `wget` to download the source code of a Pluggable Authentication Module (PAM) shared object file. Attackers may download the source code of a PAM shared object file to create a backdoor in the authentication process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/zephrax/linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)
* [https://github.com/eurialo/pambd](https://github.com/eurialo/pambd)
* [http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.html](http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.md)
* [https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html](https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4804]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name in ("curl", "wget") and
process.args like~ "https://github.com/linux-pam/linux-pam/releases/download/v*/Linux-PAM-*.tar.xz"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



