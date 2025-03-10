---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-namespace-manipulation-using-unshare.html
---

# Namespace Manipulation Using Unshare [prebuilt-rule-8-4-3-namespace-manipulation-using-unshare]

Identifies suspicious usage of unshare to manipulate system namespaces. Unshare can be utilized to escalate privileges or escape container security boundaries. Threat actors have utilized this binary to allow themselves to escape to the host and access other resources or escalate privileges.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://man7.org/linux/man-pages/man1/unshare.1.html](https://man7.org/linux/man-pages/man1/unshare.1.md)
* [https://www.crowdstrike.com/blog/cve-2022-0185-kubernetes-container-escape-using-linux-kernel-exploit/](https://www.crowdstrike.com/blog/cve-2022-0185-kubernetes-container-escape-using-linux-kernel-exploit/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Privilege Escalation
* Elastic Endgame

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4338]

```js
process where event.type == "start" and event.action : ("exec", "exec_event") and
process.executable: "/usr/bin/unshare" and
not process.parent.executable: ("/usr/bin/udevadm", "*/lib/systemd/systemd-udevd", "/usr/bin/unshare") and
not process.args : "/usr/bin/snap"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



