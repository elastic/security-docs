---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-via-electron-child-process-node-js-module.html
---

# Execution via Electron Child Process Node.js Module [execution-via-electron-child-process-node-js-module]

Identifies attempts to execute a child process from within the context of an Electron application using the child_process Node.js module. Adversaries may abuse this technique to inherit permissions from parent processes.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.matthewslipper.com/2019/09/22/everything-you-wanted-electron-child-process.html](https://www.matthewslipper.com/2019/09/22/everything-you-wanted-electron-child-process.md)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)
* [https://nodejs.org/api/child_process.html](https://nodejs.org/api/child_process.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_315]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution via Electron Child Process Node.js Module**

Electron applications, built on Node.js, can execute child processes using the `child_process` module, inheriting parent process permissions. Adversaries exploit this to execute unauthorized commands, bypassing security controls. The detection rule identifies suspicious process starts on macOS, focusing on command-line arguments indicative of such abuse, aiding in threat detection and mitigation.

**Possible investigation steps**

* Review the process arguments captured in the alert to confirm the presence of suspicious patterns, such as the use of "-e" and the inclusion of "require(*child_process*)".
* Identify the parent Electron application process to determine if it is a legitimate application or potentially malicious.
* Check the user account associated with the process to assess if it has elevated privileges that could be exploited.
* Investigate the command executed by the child process to understand its purpose and potential impact on the system.
* Correlate the alert with other security events or logs from the same host to identify any related suspicious activities or patterns.
* Examine the network activity of the host around the time of the alert to detect any unauthorized data exfiltration or communication with known malicious IPs.

**False positive analysis**

* Legitimate Electron applications may use the child_process module for valid operations, such as launching helper scripts or tools. Users should identify and whitelist these known applications to prevent unnecessary alerts.
* Development environments often execute scripts using child_process during testing or debugging. Exclude processes originating from development directories or environments to reduce false positives.
* Automated build or deployment tools running on macOS might invoke child processes as part of their workflow. Recognize and exclude these tools by their process names or paths.
* Some Electron-based applications might use command-line arguments that match the detection pattern for legitimate reasons. Review and adjust the detection rule to exclude these specific argument patterns when associated with trusted applications.
* Regularly review and update the exclusion list to accommodate new legitimate use cases as they arise, ensuring that the detection rule remains effective without generating excessive false positives.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized command execution and potential lateral movement.
* Terminate any suspicious child processes identified as being spawned by the Electron application to halt any ongoing malicious activity.
* Conduct a thorough review of the Electron application’s code and configuration to identify and remove any unauthorized or malicious scripts or modules, particularly those involving the `child_process` module.
* Revoke and reset any credentials or tokens that may have been exposed or compromised due to the unauthorized execution, ensuring that new credentials are distributed securely.
* Apply security patches and updates to the Electron application and underlying Node.js environment to mitigate any known vulnerabilities that could be exploited in a similar manner.
* Enhance monitoring and logging on the affected system and similar environments to detect any future attempts to exploit the `child_process` module, focusing on command-line arguments and process creation events.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been impacted, ensuring a comprehensive response to the threat.


## Setup [_setup_199]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_331]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and process.args:("-e" and const*require*child_process*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)



