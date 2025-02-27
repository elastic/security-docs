---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-bpf-filter-applied-using-tc.html
---

# BPF filter applied using TC [prebuilt-rule-8-3-3-bpf-filter-applied-using-tc]

Detects when the tc (transmission control) binary is utilized to set a BPF (Berkeley Packet Filter) on a network interface. Tc is used to configure Traffic Control in the Linux kernel. It can shape, schedule, police and drop traffic. A threat actor can utilize tc to set a bpf filter on an interface for the purpose of manipulating the incoming traffic. This technique is not at all common and should indicate abnormal, suspicious or malicious activity.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh](https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh)
* [https://man7.org/linux/man-pages/man8/tc.8.html](https://man7.org/linux/man-pages/man8/tc.8.md)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* TripleCross

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3393]

```js
process where event.type != "end" and process.executable : "/usr/sbin/tc" and process.args : "filter" and process.args : "add" and process.args : "bpf" and not process.parent.executable: "/usr/sbin/libvirtd"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



