---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-defense-evasion-via-proot.html
---

# Potential Defense Evasion via PRoot [prebuilt-rule-8-17-4-potential-defense-evasion-via-proot]

Identifies the execution of the PRoot utility, an open-source tool for user-space implementation of chroot, mount --bind, and binfmt_misc. Adversaries can leverage an open-source tool PRoot to expand the scope of their operations to multiple Linux distributions and simplify their necessary efforts. In a normal threat scenario, the scope of an attack is limited by the varying configurations of each Linux distribution. With PRoot, it provides an attacker with a consistent operational environment across different Linux distributions, such as Ubuntu, Fedora, and Alpine. PRoot also provides emulation capabilities that allow for malware built on other architectures, such as ARM, to be run.The post-exploitation technique called bring your own filesystem (BYOF), can be used by the threat actors to execute malicious payload or elevate privileges or perform network scans or orchestrate another attack on the environment. Although PRoot was originally not developed with malicious intent it can be easily tuned to work for one.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://proot-me.github.io/](https://proot-me.github.io/)

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

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4354]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Defense Evasion via PRoot**

PRoot is a versatile tool that emulates a chroot-like environment, allowing users to run applications across different Linux distributions seamlessly. Adversaries exploit PRoot to create consistent environments for executing malicious payloads, bypassing traditional defenses. The detection rule identifies suspicious PRoot activity by monitoring process executions initiated by PRoot, flagging potential misuse for defense evasion.

**Possible investigation steps**

* Review the process tree to identify the parent process of PRoot and any child processes it spawned, focusing on the process.parent.name field to confirm PRoot as the parent.
* Examine the command line arguments used with PRoot to understand the context of its execution and identify any potentially malicious payloads or scripts being executed.
* Check the user account associated with the PRoot process to determine if it aligns with expected usage patterns or if it indicates potential compromise.
* Investigate the network activity associated with the PRoot process to identify any unusual connections or data transfers that could suggest malicious intent.
* Correlate the PRoot activity with other security alerts or logs to identify any related suspicious behavior or indicators of compromise within the same timeframe.

**False positive analysis**

* Legitimate use of PRoot for cross-distribution development or testing environments may trigger alerts. Users can create exceptions for known development teams or specific projects that require PRoot for legitimate purposes.
* System administrators using PRoot for system maintenance or migration tasks might be flagged. To mitigate this, document and whitelist these activities by correlating them with scheduled maintenance windows or specific administrator accounts.
* Security researchers or penetration testers employing PRoot for controlled testing scenarios could cause false positives. Establish a process to identify and exclude these activities by verifying the involved personnel and their testing scope.
* Automated scripts or tools that utilize PRoot for non-malicious purposes, such as software compatibility testing, should be reviewed. Implement a tagging system to differentiate these benign activities from potential threats, allowing for easier exclusion in future detections.

**Response and remediation**

* Isolate the affected system immediately to prevent further spread of the threat across the network. Disconnect it from the network and any shared resources.
* Terminate any suspicious processes initiated by PRoot to halt any ongoing malicious activities. Use process management tools to identify and kill these processes.
* Conduct a thorough examination of the filesystem for any unauthorized changes or suspicious files that may have been introduced by the adversary using PRoot.
* Restore the system from a known good backup if any malicious modifications are detected, ensuring that the backup is free from compromise.
* Update and patch the affected system to the latest security standards to close any vulnerabilities that may have been exploited.
* Implement enhanced monitoring for PRoot activity across the environment to detect any future unauthorized use. This includes setting up alerts for any process executions with PRoot as the parent process.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_1202]

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


## Rule query [_rule_query_5346]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name == "proot"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Exploitation for Defense Evasion
    * ID: T1211
    * Reference URL: [https://attack.mitre.org/techniques/T1211/](https://attack.mitre.org/techniques/T1211/)



