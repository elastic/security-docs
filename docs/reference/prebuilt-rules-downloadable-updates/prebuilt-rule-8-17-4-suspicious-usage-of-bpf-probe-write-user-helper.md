---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-usage-of-bpf-probe-write-user-helper.html
---

# Suspicious Usage of bpf_probe_write_user Helper [prebuilt-rule-8-17-4-suspicious-usage-of-bpf-probe-write-user-helper]

This rule monitors the syslog log file for messages related to instances of a program using the `bpf_probe_write_user` helper. The `bpf_probe_write_user` helper is used to write data to user space from a BPF program. Unauthorized use of this helper can be indicative of an eBPF rootkit or other malicious activity.

**Rule type**: query

**Rule indices**:

* logs-system.syslog-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3943]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Usage of bpf_probe_write_user Helper**

The `bpf_probe_write_user` helper is a function within the eBPF (extended Berkeley Packet Filter) framework, allowing BPF programs to write data to user space. While useful for legitimate monitoring and debugging, adversaries can exploit it to manipulate user space memory, potentially deploying rootkits or evading defenses. The detection rule monitors syslog entries for kernel processes invoking this helper, flagging potential unauthorized use indicative of malicious activity.

**Possible investigation steps**

* Review the syslog entries for the specific message "bpf_probe_write_user" to identify the exact time and context of the event.
* Correlate the timestamp of the alert with other logs and system activities to identify any unusual behavior or patterns around the same time.
* Investigate the process details associated with the kernel at the time of the alert to determine if there are any anomalies or unauthorized modifications.
* Check for any recent changes or installations on the system that could have introduced unauthorized BPF programs.
* Assess the system for signs of persistence mechanisms or defense evasion tactics, as indicated by the MITRE ATT&CK framework references.
* Conduct a thorough review of user accounts and permissions to ensure no unauthorized access or privilege escalation has occurred.
* If suspicious activity is confirmed, isolate the affected system and perform a comprehensive forensic analysis to understand the scope and impact of the potential compromise.

**False positive analysis**

* Legitimate monitoring tools may use the bpf_probe_write_user helper for debugging purposes. Identify and whitelist these tools by verifying their source and ensuring they are part of authorized software packages.
* Kernel developers and system administrators might use this helper during system diagnostics or performance tuning. Establish a baseline of expected usage patterns and create exceptions for known maintenance activities.
* Automated scripts or system processes that perform regular system checks could trigger this rule. Review the scripts and processes to confirm their legitimacy and exclude them from alerts if they are verified as safe.
* Security software or intrusion detection systems might utilize this helper as part of their normal operations. Coordinate with your security team to recognize these activities and adjust the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data manipulation.
* Terminate any suspicious processes associated with the `bpf_probe_write_user` helper to halt potential malicious activity.
* Conduct a thorough review of recent system changes and installed software to identify unauthorized modifications or installations.
* Restore affected systems from a known good backup to ensure the integrity of user space memory and system files.
* Implement stricter access controls and monitoring on systems with eBPF capabilities to prevent unauthorized use of the `bpf_probe_write_user` helper.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Update detection mechanisms to include additional indicators of compromise related to eBPF rootkits and similar threats, enhancing future threat detection capabilities.


## Setup [_setup_907]

**Setup**

This rule requires data coming in from one of the following integrations: - Filebeat

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat for the Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete Setup and Run Filebeat information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the Filebeat System Module to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_4960]

```js
host.os.type:linux and event.dataset:"system.syslog" and process.name:kernel and message:"bpf_probe_write_user"
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



