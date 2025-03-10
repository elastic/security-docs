---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-kernel-module.html
---

# Creation of Kernel Module [creation-of-kernel-module]

Identifies activity related to loading kernel modules on Linux via creation of new ko files in the LKM directory.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_250]

```js
file where host.os.type == "linux" and event.type in ("change", "creation") and file.path : "/lib/modules/*" and
file.extension == "ko" and not process.name : (
  "dpkg", "systemd", "falcon-sensor*", "dnf", "yum", "rpm", "cp"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)



