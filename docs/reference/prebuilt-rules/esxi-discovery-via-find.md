---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/esxi-discovery-via-find.html
---

# ESXI Discovery via Find [esxi-discovery-via-find]

Identifies instances where the *find* command is started on a Linux system with arguments targeting specific VM-related paths, such as "/etc/vmware/", "/usr/lib/vmware/", or "/vmfs/*". These paths are associated with VMware virtualization software, and their presence in the find command arguments may indicate that a threat actor is attempting to search for, analyze, or manipulate VM-related files and configurations on the system.

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

## Investigation guide [_investigation_guide_284]

**Triage and analysis**

[TBC: QUOTE]
**Investigating ESXI Discovery via Find**

VMware ESXi is a hypervisor used to deploy and manage virtual machines. Adversaries may exploit the *find* command on Linux systems to locate VM-related files, potentially to gather information or manipulate configurations. The detection rule identifies suspicious *find* command executions targeting VMware paths, excluding legitimate processes, to flag potential reconnaissance activities.

**Possible investigation steps**

* Review the process execution details to confirm the *find* command was executed with arguments targeting VMware paths such as "/etc/vmware/**", "/usr/lib/vmware/**", or "/vmfs/*".
* Check the parent process of the *find* command to ensure it is not "/usr/lib/vmware/viewagent/bin/uninstall_viewagent.sh", which is excluded from the rule as a legitimate process.
* Investigate the user account associated with the *find* command execution to determine if it is a known and authorized user for VMware management tasks.
* Examine recent login and access logs for the user account to identify any unusual or unauthorized access patterns.
* Correlate this event with other security alerts or logs to identify if there are additional signs of reconnaissance or unauthorized activity on the system.
* Assess the system’s current state and configuration to ensure no unauthorized changes have been made to VMware-related files or settings.

**False positive analysis**

* Legitimate administrative tasks may trigger the rule if system administrators use the *find* command to audit or manage VMware-related files. To handle this, create exceptions for known administrative scripts or user accounts that regularly perform these tasks.
* Automated backup or monitoring scripts that scan VMware directories can also cause false positives. Identify these scripts and exclude their parent processes from the detection rule.
* Software updates or maintenance activities involving VMware components might execute the *find* command in a non-threatening manner. Consider scheduling these activities during known maintenance windows and temporarily adjusting the rule to prevent unnecessary alerts.
* If the *find* command is part of a legitimate software installation or uninstallation process, such as the VMware View Agent uninstallation, ensure these processes are whitelisted by adding their parent executable paths to the exception list.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious *find* processes identified in the alert to halt potential reconnaissance activities.
* Conduct a thorough review of the system’s recent command history and logs to identify any unauthorized access or changes made to VM-related files.
* Restore any altered or deleted VM-related files from a known good backup to ensure system integrity.
* Update and patch the VMware ESXi and related software to the latest versions to mitigate any known vulnerabilities.
* Implement stricter access controls and monitoring on VMware-related directories to prevent unauthorized access in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_183]

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


## Rule query [_rule_query_296]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "executed", "process_started") and
  process.name == "find" and process.args : ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*") and
  not process.parent.executable == "/usr/lib/vmware/viewagent/bin/uninstall_viewagent.sh"
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



