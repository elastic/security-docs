---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-data-splitting-detected.html
---

# Potential Data Splitting Detected [potential-data-splitting-detected]

This rule looks for the usage of common data splitting utilities with specific arguments that indicate data splitting for exfiltration on Linux systems. Data splitting is a technique used by adversaries to split data into smaller parts to avoid detection and exfiltrate data.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Exfiltration
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_671]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Data Splitting Detected**

Data splitting utilities on Linux, such as `dd` and `split`, are typically used for managing large files by dividing them into smaller, more manageable parts. Adversaries exploit these tools to covertly exfiltrate data by splitting it into inconspicuous segments. The detection rule identifies suspicious use of these utilities by monitoring specific command-line arguments and excluding benign processes, thereby flagging potential exfiltration activities.

**Possible investigation steps**

* Review the process details to confirm the use of data splitting utilities like *dd*, *split*, or *rsplit* with suspicious arguments such as *bs=***, *if=***, *-b*, or *--bytes**.
* Examine the parent process name to ensure it is not a benign process like *apport* or *overlayroot*, which are excluded in the rule.
* Investigate the source and destination paths specified in the process arguments to determine if they involve sensitive or unusual locations, excluding paths like */tmp/nvim**, */boot/**, or */dev/urandom*.
* Check the user account associated with the process to assess if it has a history of legitimate use of these utilities or if it might be compromised.
* Analyze recent network activity from the host to identify any potential data exfiltration attempts, especially if the process involves external connections.
* Correlate this alert with other security events or logs from the same host to identify any patterns or additional indicators of compromise.

**False positive analysis**

* Processes related to system maintenance or updates, such as those initiated by the *apport* or *overlayroot* processes, may trigger false positives. Users can mitigate this by ensuring these parent processes are included in the exclusion list.
* Backup operations that use *dd* or *split* for legitimate data management tasks can be mistaken for exfiltration attempts. Exclude specific backup scripts or processes by adding their unique identifiers or arguments to the exclusion criteria.
* Development or testing environments where *dd* or *split* are used for creating test data or simulating data transfer can generate false alerts. Identify and exclude these environments by specifying their process names or argument patterns.
* Automated scripts that use *dd* or *split* for routine data processing tasks should be reviewed and, if benign, added to the exclusion list to prevent unnecessary alerts.
* Regular system operations involving */dev/random*, */dev/urandom*, or similar sources should be excluded, as these are common in non-malicious contexts and are already partially covered by the rule’s exclusions.

**Response and remediation**

* Immediately isolate the affected Linux system from the network to prevent further data exfiltration.
* Terminate any suspicious processes identified by the detection rule, specifically those involving the `dd`, `split`, or `rsplit` utilities with the flagged arguments.
* Conduct a thorough review of recent file access and modification logs to identify any unauthorized data handling or exfiltration attempts.
* Restore any potentially compromised data from secure backups, ensuring that the restored data is free from any malicious alterations.
* Implement stricter access controls and monitoring on sensitive data directories to prevent unauthorized access and manipulation.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are affected.
* Enhance monitoring and alerting for similar suspicious activities by integrating additional threat intelligence sources and refining detection capabilities.


## Setup [_setup_429]

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


## Rule query [_rule_query_710]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name == "dd" and process.args like "bs=*" and process.args like "if=*") or
    (
      process.name in ("split", "rsplit") and
      (
        (process.args == "-b" or process.args like "--bytes*") or
        (process.args == "-C" or process.args like "--line-bytes*")
      )
    )
  ) and
  not (
    process.parent.name in ("apport", "overlayroot", "nessus-agent-module") or
    process.args like (
      "if=/tmp/nvim*", "if=/boot/*", "if=/dev/random", "if=/dev/urandom", "/dev/mapper/*",
      "if=*.iso", "of=/dev/stdout", "if=/dev/zero", "if=/dev/sda", "/proc/sys/kernel/*"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



