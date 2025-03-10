---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-esxi-discovery-via-grep.html
---

# ESXI Discovery via Grep [prebuilt-rule-8-17-4-esxi-discovery-via-grep]

Identifies instances where a process named *grep*, *egrep*, or *pgrep* is started on a Linux system with arguments related to virtual machine (VM) files, such as "vmdk", "vmx", "vmxf", "vmsd", "vmsn", "vswp", "vmss", "nvram", or "vmem". These file extensions are associated with VM-related file formats, and their presence in grep command arguments may indicate that a threat actor is attempting to search for, analyze, or manipulate VM files on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/](https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4365]

**Triage and analysis**

[TBC: QUOTE]
**Investigating ESXI Discovery via Grep**

In Linux environments, tools like *grep* are used to search through files for specific patterns. Adversaries may exploit these tools to locate and analyze virtual machine files, which are crucial for ESXi environments. The detection rule identifies suspicious use of *grep* variants targeting VM file extensions, signaling potential reconnaissance or manipulation attempts by threat actors. This rule helps in early detection of such malicious activities by monitoring process execution patterns.

**Possible investigation steps**

* Review the process execution details to confirm the presence of *grep*, *egrep*, or *pgrep* with arguments related to VM file extensions such as "vmdk", "vmx", "vmxf", "vmsd", "vmsn", "vswp", "vmss", "nvram", or "vmem".
* Check the parent process of the suspicious *grep* command to determine if it is a legitimate process or potentially malicious, ensuring it is not "/usr/share/qemu/init/qemu-kvm-init".
* Investigate the user account associated with the process execution to assess if the activity aligns with their typical behavior or if it appears anomalous.
* Examine recent system logs and other security alerts for additional indicators of compromise or related suspicious activities on the host.
* Assess the network activity from the host to identify any unusual connections or data exfiltration attempts that may correlate with the discovery activity.

**False positive analysis**

* System administrators or automated scripts may use grep to search for VM-related files as part of routine maintenance or monitoring tasks. To handle this, create exceptions for known administrative scripts or processes by excluding specific parent processes or user accounts.
* Backup or snapshot management tools might invoke grep to verify the presence of VM files. Identify these tools and exclude their process names or paths from the detection rule to prevent false alerts.
* Developers or IT staff conducting legitimate audits or inventory checks on VM files may trigger this rule. Consider excluding specific user accounts or groups that are authorized to perform such activities.
* Security tools or monitoring solutions that perform regular checks on VM files could also cause false positives. Whitelist these tools by excluding their executable paths or process names from the rule.

**Response and remediation**

* Isolate the affected Linux system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, specifically those involving *grep*, *egrep*, or *pgrep* with VM-related file extensions.
* Conduct a thorough review of the system’s recent process execution history and file access logs to identify any unauthorized access or changes to VM files.
* Restore any compromised or altered VM files from a known good backup to ensure system integrity and continuity.
* Implement stricter access controls and permissions on VM-related files to limit exposure to unauthorized users or processes.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Update and enhance monitoring rules to detect similar patterns of suspicious activity, ensuring early detection of future threats.


## Setup [_setup_1212]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5357]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "executed", "process_started") and
  process.name in ("grep", "egrep", "pgrep") and
  process.args in ("vmdk", "vmx", "vmxf", "vmsd", "vmsn", "vswp", "vmss", "nvram", "vmem") and
  not process.parent.executable == "/usr/share/qemu/init/qemu-kvm-init"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)



