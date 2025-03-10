---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kernel-seeking-activity.html
---

# Kernel Seeking Activity [kernel-seeking-activity]

This rule detects kernel seeking activity through several built-in Linux utilities. Attackers may use these utilities to search the Linux kernel for available symbols, functions, and other information that can be used to exploit the kernel.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/declawing-pumakit](https://www.elastic.co/security-labs/declawing-pumakit)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_451]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Seeking Activity**

Kernel seeking involves probing the Linux kernel for symbols and functions, often using utilities like `tail`, `cmp`, `hexdump`, `xxd`, and `dd`. Adversaries exploit this to discover vulnerabilities for kernel exploitation. The detection rule identifies suspicious execution patterns of these utilities, particularly when accessing kernel-related paths, signaling potential malicious reconnaissance or exploitation attempts.

**Possible investigation steps**

* Review the process execution details to confirm the use of utilities like `tail`, `cmp`, `hexdump`, `xxd`, or `dd` with the specified arguments, focusing on the `process.name` and `process.args` fields.
* Examine the `process.parent.args` and `process.args` fields to identify the specific kernel-related paths accessed, such as those under `/boot/*`, to understand the context of the access.
* Investigate the parent process of the suspicious activity by analyzing the `process.parent` field to determine if it was initiated by a legitimate or potentially malicious process.
* Check the timeline of events around the alert to identify any preceding or subsequent suspicious activities that might indicate a broader attack pattern.
* Correlate the alert with other security events or logs from the same host to assess if there are additional indicators of compromise or related malicious activities.
* Evaluate the user account associated with the process execution to determine if it aligns with expected behavior or if it might be compromised.

**False positive analysis**

* System administrators or automated scripts may use utilities like `tail`, `cmp`, `hexdump`, `xxd`, and `dd` for legitimate maintenance tasks involving kernel files. To mitigate this, identify and whitelist specific scripts or processes that are known to perform these actions regularly.
* Backup or recovery operations might involve accessing kernel-related paths with these utilities. Exclude these operations by defining exceptions for known backup tools or processes that interact with the `/boot` directory.
* Developers working on kernel modules or custom kernel builds may trigger this rule during their normal workflow. Consider excluding specific user accounts or development environments from this rule to prevent false positives.
* Security tools or monitoring solutions that perform regular checks on kernel files could be mistakenly flagged. Review and whitelist these tools to ensure they are not incorrectly identified as threats.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, particularly those involving the utilities `tail`, `cmp`, `hexdump`, `xxd`, and `dd` accessing kernel paths.
* Conduct a thorough review of system logs and process execution history to identify any additional suspicious activities or related indicators of compromise.
* Restore the system from a known good backup if any unauthorized modifications to the kernel or system files are detected.
* Update the Linux kernel and all related packages to the latest versions to patch any known vulnerabilities that could be exploited.
* Implement enhanced monitoring and alerting for similar activities, focusing on the execution of the specified utilities with kernel-related arguments.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.


## Setup [_setup_287]

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


## Rule query [_rule_query_486]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
(process.parent.args like "/boot/*" or process.args like "/boot/*") and (
  (process.name == "tail" and (process.args like "-c*" or process.args == "--bytes")) or
  (process.name == "cmp" and process.args == "-i") or
  (process.name in ("hexdump", "xxd") and process.args == "-s") or
  (process.name == "dd" and process.args like "seek*")
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



