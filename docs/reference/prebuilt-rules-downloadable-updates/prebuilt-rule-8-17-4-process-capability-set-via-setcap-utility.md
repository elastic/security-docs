---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-capability-set-via-setcap-utility.html
---

# Process Capability Set via setcap Utility [prebuilt-rule-8-17-4-process-capability-set-via-setcap-utility]

This rule detects the use of the setcap utility to set capabilities on a process. The setcap utility is used to set the capabilities of a binary to allow it to perform privileged operations without needing to run as root. This can be used by attackers to establish persistence by creating a backdoor, or escalate privileges by abusing a misconfiguration on a system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4481]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Capability Set via setcap Utility**

The `setcap` utility in Linux assigns specific capabilities to executables, allowing them to perform privileged tasks without full root access. While beneficial for security, adversaries can exploit this to maintain persistence or escalate privileges by misconfiguring capabilities. The detection rule identifies suspicious `setcap` usage by monitoring process execution patterns, excluding benign parent processes, to flag potential misuse.

**Possible investigation steps**

* Review the process execution details to confirm the use of the setcap utility, focusing on the process name and event action fields to ensure the alert is not a false positive.
* Investigate the parent process executable and name to determine if the setcap command was executed by a potentially malicious or unexpected process, especially if it is not among the excluded benign parent processes.
* Check the capabilities that were set by the setcap command to assess if they could allow privilege escalation or persistence, and determine if they align with normal operational requirements.
* Examine the timeline of events around the setcap execution to identify any preceding or subsequent suspicious activities that might indicate a broader attack or compromise.
* Correlate the alert with other security events or logs from the same host to identify any patterns or additional indicators of compromise that could suggest a coordinated attack.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule when package managers like dpkg or Docker set capabilities during their processes. To handle this, exclude paths such as /var/lib/dpkg/* and /var/lib/docker/* from the detection rule.
* Development environments or containerized applications might use setcap for testing purposes. Exclude processes originating from /tmp/newroot/* and /var/tmp/newroot/* to reduce noise from these environments.
* Custom scripts or administrative tools that use setcap for legitimate configuration tasks can be excluded by identifying their parent process names and adding them to the exclusion list, similar to the existing exclusions for jem and vzctl.
* Regular audits of the exclusion list should be conducted to ensure that no malicious processes are inadvertently whitelisted, maintaining a balance between reducing false positives and ensuring security.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the attacker.
* Terminate any suspicious processes associated with the `setcap` utility that are not part of legitimate administrative tasks.
* Review and remove any unnecessary capabilities set on executables using the `setcap` utility to prevent privilege escalation.
* Conduct a thorough audit of the system to identify any backdoors or unauthorized changes made by the attacker, and remove them.
* Restore affected systems from a known good backup if unauthorized changes or persistent threats are detected.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and logging for `setcap` usage and similar privilege escalation attempts to improve future detection capabilities.


## Setup [_setup_1319]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5473]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name == "setcap" and not (
  process.parent.executable == null or
  process.parent.executable : ("/var/lib/dpkg/*", "/var/lib/docker/*", "/tmp/newroot/*", "/var/tmp/newroot/*") or
  process.parent.name in ("jem", "vzctl")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



