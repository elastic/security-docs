---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-manual-dracut-execution.html
---

# Manual Dracut Execution [prebuilt-rule-8-17-4-manual-dracut-execution]

This rule detects manual execution of the `dracut` command on Linux systems. Dracut is a tool used to generate an initramfs image that is used to boot the system. Attackers may use `dracut` to create a custom initramfs image that includes malicious code or backdoors, allowing them to maintain persistence on the system.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4471]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Manual Dracut Execution**

Dracut is a utility in Linux systems used to create initramfs images, essential for booting. Adversaries might exploit Dracut to craft malicious initramfs, embedding backdoors for persistence. The detection rule identifies unusual Dracut executions by scrutinizing process origins and excluding legitimate parent processes, flagging potential unauthorized use.

**Possible investigation steps**

* Review the process details to confirm the execution of the dracut command, focusing on the process.name and process.parent.executable fields to identify any unusual parent processes.
* Examine the command line arguments used with the dracut process by checking the process.parent.command_line field to understand the context of its execution.
* Investigate the user account associated with the dracut execution to determine if it aligns with expected administrative activity or if it indicates potential unauthorized access.
* Check the system logs and any related security alerts around the time of the dracut execution to identify any correlated suspicious activities or anomalies.
* Assess the system for any changes to the initramfs image or other boot-related files that could indicate tampering or the presence of backdoors.

**False positive analysis**

* Legitimate system updates or kernel installations may trigger the rule. To handle this, users can create exceptions for processes originating from known update paths like /usr/lib/kernel/* or /etc/kernel/install.d/*.
* Automated scripts or maintenance tasks that use dracut for legitimate purposes might be flagged. Users should identify these scripts and add their parent process names, such as dracut-install or run-parts, to the exclusion list.
* Custom administrative scripts executed by trusted users could be mistaken for suspicious activity. Users can exclude specific command lines or arguments associated with these scripts, such as /usr/bin/dracut-rebuild, to prevent false positives.
* Temporary or testing environments where dracut is used for non-malicious testing purposes might trigger alerts. Users can exclude these environments by specifying unique parent process paths or names that are characteristic of the testing setup.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Terminate any suspicious or unauthorized dracut processes identified on the system to halt any ongoing malicious activity.
* Conduct a thorough review of the initramfs images on the affected system to identify and remove any unauthorized or malicious modifications.
* Restore the system’s initramfs from a known good backup to ensure the integrity of the boot process.
* Implement monitoring for any future unauthorized dracut executions by setting up alerts for similar process activities, ensuring quick detection and response.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Review and update access controls and permissions to limit the ability to execute dracut to only authorized personnel, reducing the risk of future exploitation.


## Setup [_setup_1313]

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


## Rule query [_rule_query_5463]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name == "dracut" and process.parent.executable != null and not (
  process.parent.executable like~ (
    "/usr/lib/kernel/*", "/etc/kernel/install.d/*", "/var/lib/dpkg/info/dracut.postinst",
    "/tmp/newroot/*", "/usr/lib/module-init-tools/*"
  ) or
  process.parent.name in (
    "dracut-install", "dracut", "run-parts", "weak-modules", "mkdumprd", "new-kernel-pkg", "sudo"
  ) or
  process.parent.args like~ ("/usr/bin/dracut-rebuild", "/var/tmp/rpm-tmp.*") or
  process.parent.command_line like~ "/bin/sh -c if command -v mkinitcpio*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Pre-OS Boot
    * ID: T1542
    * Reference URL: [https://attack.mitre.org/techniques/T1542/](https://attack.mitre.org/techniques/T1542/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



