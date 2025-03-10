---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-process-name-stomping-with-prctl.html
---

# Potential Process Name Stomping with Prctl [prebuilt-rule-8-17-3-potential-process-name-stomping-with-prctl]

This rule leverages Auditd data to detect the use of the `prctl` syscall to potentially hide a process by changing its name. The `prctl` syscall is used to control various process attributes. Attackers can use this syscall to change the name of a process to a hidden directory or file, making it harder to detect. The query looks for the `prctl` syscall with the `PR_SET_NAME` argument set to `f` (PR_SET_NAME is used to set the name of a process).

**Rule type**: eql

**Rule indices**:

* logs-auditd_manager.auditd-*
* auditbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://haxrob.net/process-name-stomping/](https://haxrob.net/process-name-stomping/)
* [https://haxrob.net/hiding-in-plain-sight-part-2/](https://haxrob.net/hiding-in-plain-sight-part-2/)
* [https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd](https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd)

**Tags**:

* Data Source: Auditd Manager
* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_792]

**Setup**

This rule requires data coming in from Auditd Manager.

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" on a Linux System:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration:  — "-a exit,always -F arch=b64 -S prctl -k prctl_detection"


## Rule query [_rule_query_4825]

```js
process where host.os.type == "linux" and auditd.data.syscall == "prctl" and auditd.data.a0 == "f" and
process.executable like (
  "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/var/run/*", "/etc/update-motd.d/*",
  "/tmp/*", "/var/log/*", "/var/tmp/*", "/home/*", "/run/shm/*", "/run/*", "./*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)



