---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-dynamic-linker-discovery-via-od.html
---

# Suspicious Dynamic Linker Discovery via od [suspicious-dynamic-linker-discovery-via-od]

Monitors for dynamic linker discovery via the od utility. od (octal dump) is a command-line utility in Unix operating systems used for displaying data in various formats, including octal, hexadecimal, decimal, and ASCII, primarily used for examining and debugging binary files or data streams. Attackers can leverage od to analyze the dynamic linker by identifying injection points and craft exploits based on the observed behaviors and structures within these files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_979]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Dynamic Linker Discovery via od**

The dynamic linker in Linux environments is crucial for loading shared libraries needed by programs. Attackers may exploit the `od` utility to inspect these linkers, seeking vulnerabilities for code injection. The detection rule identifies suspicious use of `od` targeting specific linker files, flagging potential reconnaissance activities that could precede an exploit attempt.

**Possible investigation steps**

* Review the process execution details to confirm the use of the *od* utility, focusing on the process name and arguments to ensure they match the suspicious patterns identified in the query.
* Investigate the user account associated with the process execution to determine if the activity aligns with their typical behavior or if it appears anomalous.
* Check the system’s process execution history for any other unusual or related activities around the same time, such as attempts to access or modify linker files.
* Analyze any network connections or data transfers initiated by the host around the time of the alert to identify potential data exfiltration or communication with known malicious IPs.
* Correlate this event with other security alerts or logs from the same host to identify patterns or sequences of actions that could indicate a broader attack campaign.

**False positive analysis**

* System administrators or developers may use the od utility to inspect dynamic linker files for legitimate debugging or system maintenance purposes. To handle this, create exceptions for known user accounts or processes that regularly perform these activities.
* Automated scripts or monitoring tools might invoke od on dynamic linker files as part of routine system checks. Identify these scripts and whitelist their execution paths to prevent unnecessary alerts.
* Security researchers or penetration testers could use od during authorized security assessments. Establish a process to temporarily disable the rule or add exceptions for the duration of the assessment to avoid false positives.
* Some software installations or updates might involve the use of od to verify linker integrity. Monitor installation logs and correlate with od usage to determine if the activity is benign, and consider adding exceptions for these specific scenarios.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or further exploitation.
* Terminate any suspicious processes associated with the `od` utility that are targeting dynamic linker files to halt any ongoing reconnaissance or exploitation attempts.
* Conduct a thorough review of system logs and process execution history to identify any unauthorized access or modifications to the dynamic linker files.
* Restore any altered or compromised dynamic linker files from a known good backup to ensure system integrity.
* Implement stricter access controls and monitoring on critical system files, including dynamic linkers, to prevent unauthorized access and modifications.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected or if there is a broader threat campaign.
* Update detection and monitoring systems to enhance visibility and alerting for similar suspicious activities involving the `od` utility and critical system files.


## Setup [_setup_622]

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


## Rule query [_rule_query_1027]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "od" and process.args in (
  "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
  "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
)
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



