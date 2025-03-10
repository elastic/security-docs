---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempted-private-key-access.html
---

# Attempted Private Key Access [attempted-private-key-access]

Attackers may try to access private keys, e.g. ssh, in order to gain further authenticated access to the environment.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_172]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.command_line : ("*.pem *", "*.pem", "*.id_rsa*") and
  not process.args : (
        "--rootcert",
        "--cert",
        "--crlfile"
  ) and
  not process.command_line : (
        "*--cacert*",
        "*--ssl-cert*",
        "*--tls-cert*",
        "*--tls_server_certs*"
  ) and
  not process.executable : (
    "?:\\ProgramData\\Logishrd\\LogiOptions\\Software\\*\\LogiLuUpdater.exe",
    "?:\\Program Files\\Elastic\\Agent\\data\\*\\osqueryd.exe",
    "?:\\Program Files\\Git\\cmd\\git.exe",
    "?:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    "?:\\Program Files\\Guardicore\\gc-controller.exe",
    "?:\\Program Files\\Guardicore\\gc-deception-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-detection-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-enforcement-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-guest-agent.exe",
    "?:\\Program Files\\Logi\\LogiBolt\\LogiBoltUpdater.exe",
    "?:\\Program Files (x86)\\Schneider Electric EcoStruxure\\Building Operation 5.0\\Device Administrator\\Python\\python.exe",
    "?:\\Program Files\\Splunk\\bin\\openssl.exe",
    "?:\\Program Files\\SplunkUniversalForwarder\\bin\\openssl.exe",
    "?:\\Users\\*\\AppData\\Local\\Logi\\LogiBolt\\LogiBoltUpdater.exe",
    "?:\\Windows\\system32\\icacls.exe",
    "?:\\Windows\\System32\\OpenSSH\\*"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Private Keys
    * ID: T1552.004
    * Reference URL: [https://attack.mitre.org/techniques/T1552/004/](https://attack.mitre.org/techniques/T1552/004/)



