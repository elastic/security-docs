---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-outgoing-rdp-connection-by-unusual-process.html
---

# Potential Outgoing RDP Connection by Unusual Process [potential-outgoing-rdp-connection-by-unusual-process]

Adversaries may attempt to connect to a remote system over Windows Remote Desktop Protocol (RDP) to achieve lateral movement. Adversaries may avoid using the Microsoft Terminal Services Client (mstsc.exe) binary to establish an RDP connection to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.network-*

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
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_765]

```js
network where host.os.type == "windows" and
  event.action == "connection_attempted" and destination.port == 3389 and
  destination.ip != "::1" and destination.ip != "127.0.0.1" and
  not (
    process.executable : (
      "?:\\Windows\\System32\\mstsc.exe",
      "?:\\Program Files (x86)\\mRemoteNG\\mRemoteNG.exe",
      "?:\\Program Files (x86)\\PRTG Network Monitor\\PRTG Probe.exe",
      "?:\\Program Files\\Azure Advanced Threat Protection Sensor\\*\\Microsoft.Tri.Sensor.exe",
      "?:\\Program Files (x86)\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.exe",
      "?:\\Program Files\\SentinelOne\\Sentinel Agent*\\Ranger\\SentinelRanger.exe",
      "?:\\Program Files\\Devolutions\\Remote Desktop Manager\\RemoteDesktopManager.exe",
      "?:\\Program Files (x86)\\Devolutions\\Remote Desktop Manager\\RemoteDesktopManager.exe"
    ) and process.code_signature.trusted == true
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Remote Desktop Protocol
    * ID: T1021.001
    * Reference URL: [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)



