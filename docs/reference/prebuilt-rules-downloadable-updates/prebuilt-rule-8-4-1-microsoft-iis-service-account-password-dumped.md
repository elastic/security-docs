---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-microsoft-iis-service-account-password-dumped.html
---

# Microsoft IIS Service Account Password Dumped [prebuilt-rule-8-4-1-microsoft-iis-service-account-password-dumped]

Identifies the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords. An attacker with IIS web server access via a web shell can decrypt and dump the IIS AppPool service account password using AppCmd.

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

**Maximum alerts per execution**: 33

**References**:

* [https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2688]



## Rule query [_rule_query_3078]

```js
process where event.type == "start" and
   (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and
   process.args : "/list" and process.args : "/text*password"
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



