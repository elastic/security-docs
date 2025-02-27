---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-wireless-credential-dumping-using-netsh-command.html
---

# Wireless Credential Dumping using Netsh Command [prebuilt-rule-8-4-2-wireless-credential-dumping-using-netsh-command]

Identifies attempts to dump Wireless saved access keys in clear text using the Windows built-in utility Netsh.

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

* [https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts)
* [https://www.geeksforgeeks.org/how-to-find-the-wi-fi-password-using-cmd-in-windows/](https://www.geeksforgeeks.org/how-to-find-the-wi-fi-password-using-cmd-in-windows/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Discovery
* Elastic Endgame

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3385]



## Rule query [_rule_query_4026]

```js
process where event.type == "start" and
 (process.name : "netsh.exe" or process.pe.original_file_name == "netsh.exe") and
  process.args : "wlan" and process.args : "key*clear"
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

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



