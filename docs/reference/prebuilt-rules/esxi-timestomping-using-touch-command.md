---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/esxi-timestomping-using-touch-command.html
---

# ESXI Timestomping using Touch Command [esxi-timestomping-using-touch-command]

Identifies instances where the *touch* command is executed on a Linux system with the "-r" flag, which is used to modify the timestamp of a file based on another file’s timestamp. The rule targets specific VM-related paths, such as "/etc/vmware/", "/usr/lib/vmware/", or "/vmfs/*". These paths are associated with VMware virtualization software, and their presence in the touch command arguments may indicate that a threat actor is attempting to tamper with timestamps of VM-related files and configurations on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
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
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_286]

**Triage and analysis**

[TBC: QUOTE]
**Investigating ESXI Timestomping using Touch Command**

VMware ESXi is a hypervisor used to manage virtual machines. Adversaries may exploit the *touch* command with the "-r" flag to alter file timestamps, masking unauthorized changes in VM-related directories. The detection rule identifies such activities by monitoring the execution of *touch* with specific arguments, signaling potential timestamp tampering in critical VMware paths.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the *touch* command with the "-r" flag and verify the specific VM-related paths involved, such as "/etc/vmware/", "/usr/lib/vmware/", or "/vmfs/*".
* Check the user account associated with the process execution to determine if it is a legitimate user or potentially compromised account.
* Investigate the parent process of the *touch* command to understand the context of its execution and identify any related suspicious activities.
* Examine recent changes to the files in the specified paths to identify any unauthorized modifications or anomalies.
* Correlate the event with other security alerts or logs from the same host to identify patterns or additional indicators of compromise.
* Assess the system for any signs of unauthorized access or other defense evasion techniques that may have been employed by the threat actor.

**False positive analysis**

* Routine administrative tasks in VMware environments may trigger the rule if administrators use the touch command with the -r flag for legitimate purposes. To manage this, create exceptions for known administrative scripts or processes that regularly perform these actions.
* Automated backup or synchronization tools that update file timestamps as part of their normal operation can cause false positives. Identify these tools and exclude their processes from the rule to prevent unnecessary alerts.
* System maintenance activities, such as updates or patches, might involve timestamp modifications in VMware directories. Coordinate with IT teams to whitelist these activities during scheduled maintenance windows.
* Custom scripts developed in-house for managing VMware environments might use the touch command with the -r flag. Review these scripts and, if verified as safe, add them to an exception list to avoid false positives.
* Security tools or monitoring solutions that perform integrity checks on VMware files may inadvertently alter timestamps. Ensure these tools are recognized and excluded from the rule to maintain accurate threat detection.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or tampering with VMware-related files.
* Conduct a thorough review of the affected system’s logs and processes to identify any unauthorized changes or additional malicious activities.
* Restore the original timestamps of the affected files using verified backups to ensure the integrity of the VMware-related configurations.
* Revert any unauthorized changes to the VMware environment by restoring from a known good backup or snapshot.
* Update and patch the VMware ESXi and associated software to the latest versions to mitigate any known vulnerabilities that could be exploited.
* Implement stricter access controls and monitoring on critical VMware directories to prevent unauthorized modifications in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_185]

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


## Rule query [_rule_query_298]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name == "touch" and process.args == "-r" and process.args : ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Timestomp
    * ID: T1070.006
    * Reference URL: [https://attack.mitre.org/techniques/T1070/006/](https://attack.mitre.org/techniques/T1070/006/)



