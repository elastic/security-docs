---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-proc-pseudo-file-system-enumeration.html
---

# Suspicious Proc Pseudo File System Enumeration [suspicious-proc-pseudo-file-system-enumeration]

This rule monitors for a rapid enumeration of 25 different proc cmd, stat, and exe files, which suggests an abnormal activity pattern. Such behavior could be an indicator of a malicious process scanning or gathering information about running processes, potentially for reconnaissance, privilege escalation, or identifying vulnerable targets.

**Rule type**: threshold

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

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_643]

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
-w /proc/ -p r -k audit_proc
```

Add the newly installed `auditd manager` to an agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.


## Rule query [_rule_query_1073]

```js
host.os.type:linux and event.category:file and event.action:"opened-file" and
file.path : (/proc/*/cmdline or /proc/*/stat or /proc/*/exe) and not process.name : (
  ps or netstat or landscape-sysin or w or pgrep or pidof or needrestart or apparmor_status
) and not process.parent.pid : 1
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



