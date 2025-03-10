---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/hidden-directory-creation-via-unusual-parent.html
---

# Hidden Directory Creation via Unusual Parent [hidden-directory-creation-via-unusual-parent]

This rule detects the creation of a hidden directory via an unusual parent executable. Hidden directories are directories that are not visible to the user by default. They are often used by attackers to hide malicious files or tools.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Tactic: Persistence
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_406]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Hidden Directory Creation via Unusual Parent**

In Linux environments, hidden directories, often prefixed with a dot, are typically used for configuration files but can be exploited by attackers to conceal malicious activities. Adversaries may create these directories using unexpected parent processes in sensitive locations. The detection rule identifies such anomalies by monitoring directory creation commands executed by unusual parent executables, focusing on specific directories and excluding known benign patterns.

**Possible investigation steps**

* Review the process.parent.executable field to identify the parent process that initiated the directory creation and assess its legitimacy based on its typical behavior and location.
* Examine the process.args field to understand the specific arguments used with the mkdir command, focusing on the directory path and any patterns that may indicate malicious intent.
* Check the process.command_line field for any unusual or suspicious command-line patterns that might suggest an attempt to evade detection.
* Investigate the context of the parent process by reviewing recent activities or logs associated with it, especially if it originates from sensitive directories like /dev/shm, /tmp, or /var/tmp.
* Correlate the alert with other security events or logs from the same host to identify any related suspicious activities or patterns that could indicate a broader attack or compromise.
* Consult threat intelligence sources or databases to determine if the parent executable or directory path has been associated with known malicious activities or threat actors.

**False positive analysis**

* Temporary directories used by legitimate applications can trigger false positives. Exclude known benign parent executables like those in "/tmp/newroot/**" or "/run/containerd/**" to reduce noise.
* Automated build processes may create hidden directories during software compilation. Add exceptions for parent executables such as "/var/tmp/buildah*" or "/tmp/python-build.*" to prevent unnecessary alerts.
* Development tools and scripts might create hidden directories for caching or temporary storage. Consider excluding parent executables like "/tmp/pear/temp/*" or "/tmp/cliphist-wofi-img" if they are part of regular development activities.
* Ensure that the command line patterns like "mkdir -p ." or "mkdir ./*" are excluded, as these are common in scripts and do not typically indicate malicious intent.
* Regularly review and update the list of excluded patterns and parent executables to align with changes in the environment and reduce false positives effectively.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes associated with the unusual parent executable identified in the alert to halt potential malicious operations.
* Conduct a thorough review of the hidden directory and its contents to identify and remove any malicious files or tools.
* Restore any affected files or configurations from a known good backup to ensure system integrity.
* Implement stricter access controls and monitoring on sensitive directories to prevent unauthorized directory creation.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are compromised.
* Update and enhance endpoint detection and response (EDR) solutions to improve detection capabilities for similar threats in the future.


## Setup [_setup_263]

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


## Rule query [_rule_query_441]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "exec_event") and
process.name == "mkdir" and process.parent.executable like (
  "/dev/shm/*", "/tmp/*", "/var/tmp/*", "/var/run/*", "/root/*", "/boot/*", "/var/www/html/*", "/opt/.*"
) and process.args like (".*", "/*/.*") and process.args_count <= 3 and not (
  process.parent.executable like ("/tmp/newroot/*", "/run/containerd/*") or
  process.command_line like ("mkdir -p .", "mkdir ./*") or
  process.args == "/root/.ssh" or
  process.parent.executable like (
    "/tmp/pear/temp/*", "/var/tmp/buildah*", "/tmp/python-build.*", "/tmp/cliphist-wofi-img", "/tmp/snap.rootfs_*"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



