---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/executable-masquerading-as-kernel-process.html
---

# Executable Masquerading as Kernel Process [executable-masquerading-as-kernel-process]

Monitors for kernel processes with associated process executable fields that are not empty. Unix kernel processes such as kthreadd and kworker typically do not have process.executable fields associated to them. Attackers may attempt to hide their malicious programs by masquerading as legitimate kernel processes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://sandflysecurity.com/blog/linux-stealth-rootkit-malware-with-edr-evasion-analyzed/](https://sandflysecurity.com/blog/linux-stealth-rootkit-malware-with-edr-evasion-analyzed/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_307]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Executable Masquerading as Kernel Process**

In Linux environments, kernel processes like `kthreadd` and `kworker` typically run without associated executable paths. Adversaries exploit this by naming malicious executables after these processes to evade detection. The detection rule identifies anomalies by flagging kernel-named processes with non-empty executable fields, indicating potential masquerading attempts. This helps in uncovering stealthy threats that mimic legitimate system activities.

**Possible investigation steps**

* Review the process details for the flagged process, focusing on the process.executable field to identify the path and name of the executable. This can provide initial insights into whether the executable is legitimate or potentially malicious.
* Check the process’s parent process (process.parent) to understand the context in which the process was started. This can help determine if the process was spawned by a legitimate system process or a suspicious one.
* Investigate the file at the path specified in the process.executable field. Verify its legitimacy by checking its hash against known malware databases or using a file reputation service.
* Examine the process’s command line arguments (process.command_line) for any unusual or suspicious parameters that might indicate malicious activity.
* Review recent system logs and events around the time the process was started to identify any related activities or anomalies that could provide additional context or evidence of compromise.
* If available, use threat intelligence sources to check for any known indicators of compromise (IOCs) related to the process name or executable path.

**False positive analysis**

* Custom scripts or administrative tools may be named similarly to kernel processes for convenience or organizational standards. Review these scripts and tools to ensure they are legitimate and consider adding them to an exception list if verified.
* Some legitimate software or monitoring tools might use kernel-like names for their processes to integrate closely with system operations. Verify the source and purpose of these processes and exclude them if they are confirmed to be non-malicious.
* System updates or patches might temporarily create processes with kernel-like names that have executable paths. Monitor these occurrences and exclude them if they are part of a verified update process.
* Development or testing environments may intentionally use kernel-like names for process simulation. Ensure these environments are isolated and add exceptions for these processes if they are part of controlled testing scenarios.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate the suspicious process immediately to stop any ongoing malicious actions. Use process management tools to kill the process identified by the alert.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise (IOCs) and assess the extent of the intrusion.
* Remove any malicious executables or files associated with the masquerading process from the system to ensure complete remediation.
* Restore the system from a known good backup if the integrity of the system is compromised, ensuring that the backup is free from any malicious artifacts.
* Update and patch the system to close any vulnerabilities that may have been exploited by the attacker, ensuring all software and security tools are up to date.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_198]

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


## Rule query [_rule_query_322]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name : ("kworker*", "kthread*") and process.executable != null
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

    * Name: Masquerade Task or Service
    * ID: T1036.004
    * Reference URL: [https://attack.mitre.org/techniques/T1036/004/](https://attack.mitre.org/techniques/T1036/004/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)



