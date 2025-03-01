---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-iis-service-account-password-dumped.html
---

# Microsoft IIS Service Account Password Dumped [microsoft-iis-service-account-password-dumped]

Identifies the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords. An attacker with IIS web server access via a web shell can decrypt and dump the IIS AppPool service account password using AppCmd.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*
* endgame-*
* logs-system.security*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: System

**Version**: 214

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_574]

```js
process where host.os.type == "windows" and event.type == "start" and
   (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
   process.args : "list" and process.args : "/text*"
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



