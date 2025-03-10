---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-modprobe-file-event.html
---

# Suspicious Modprobe File Event [suspicious-modprobe-file-event]

Detects file events involving kernel modules in modprobe configuration files, which may indicate unauthorized access or manipulation of critical kernel modules. Attackers may tamper with the modprobe files to load malicious or unauthorized kernel modules, potentially bypassing security measures, escalating privileges, or hiding their activities within the system.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Auditd Manager
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_636]

**Setup**

This rule requires the use of the `auditd_manager` integration. `Auditd_manager` is a tool designed to simplify and enhance the management of the audit subsystem in Linux systems. It provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system. The following steps should be executed in order to install and deploy `auditd_manager` on a Linux system.

```
Kibana -->
Management -->
Integrations -->
Auditd Manager -->
Add Auditd Manager
```

`Auditd_manager` subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from.

For this detection rule to trigger, the following additional audit rules are required to be added to the integration:

```
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d -p wa -k modprobe
```

Add the newly installed `auditd manager` to an agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.


## Rule query [_rule_query_1058]

```js
host.os.type:linux and event.category:file and event.action:"opened-file" and
file.path : ("/etc/modprobe.conf" or "/etc/modprobe.d" or /etc/modprobe.d/*) and not process.name:(
  cp or dpkg or dockerd or lynis or mkinitramfs or snapd or systemd-udevd or borg or auditbeat or lspci or
  aide or modprobe or python*
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



