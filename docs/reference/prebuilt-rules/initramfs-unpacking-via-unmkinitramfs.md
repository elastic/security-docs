---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/initramfs-unpacking-via-unmkinitramfs.html
---

# Initramfs Unpacking via unmkinitramfs [initramfs-unpacking-via-unmkinitramfs]

This rule detects the unpacking of an initramfs image using the `unmkinitramfs` command on Linux systems. The `unmkinitramfs` command is used to extract the contents of an initramfs image, which is used to boot the system. Attackers may use `unmkinitramfs` to unpack an initramfs image and modify its contents to include malicious code or backdoors, allowing them to maintain persistence on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_432]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Initramfs Unpacking via unmkinitramfs**

Initramfs is a crucial component in Linux boot processes, containing essential drivers and scripts. The `unmkinitramfs` tool extracts its contents, which attackers might exploit to insert malicious code, ensuring persistence. The detection rule identifies the execution of `unmkinitramfs`, flagging potential unauthorized modifications by monitoring process initiation events on Linux systems.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the unmkinitramfs command, focusing on the process.name field to ensure it matches "unmkinitramfs".
* Check the user context under which the unmkinitramfs command was executed to determine if it aligns with expected administrative activities or if it was run by an unauthorized user.
* Investigate the parent process of the unmkinitramfs execution to understand how the command was initiated and if it was part of a legitimate script or an unexpected process chain.
* Examine recent system logs and audit logs for any other suspicious activities or anomalies around the time of the unmkinitramfs execution, such as unauthorized access attempts or changes to critical system files.
* Assess the integrity of the initramfs image by comparing it with a known good version, if available, to identify any unauthorized modifications or inclusions of malicious code.

**False positive analysis**

* Routine system maintenance or updates may trigger the rule when legitimate processes unpack initramfs for kernel updates. Users can create exceptions for known maintenance scripts or processes that regularly perform these actions.
* Automated backup or recovery solutions might use unmkinitramfs to verify or restore system images. Identify and exclude these processes if they are part of trusted backup operations.
* Developers or system administrators testing or customizing initramfs images for legitimate purposes could trigger the rule. Establish a whitelist for specific user accounts or scripts that are authorized to perform these tasks.
* Security tools or monitoring solutions that analyze initramfs contents for integrity checks might inadvertently trigger the rule. Ensure these tools are recognized and excluded from detection to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or data exfiltration by the attacker.
* Terminate any suspicious processes related to `unmkinitramfs` to halt any ongoing malicious activity.
* Conduct a thorough review of the initramfs image and its contents to identify and remove any unauthorized modifications or malicious code.
* Restore the initramfs image from a known good backup to ensure system integrity and remove any potential backdoors.
* Monitor the system for any further attempts to execute `unmkinitramfs` and investigate any such occurrences to determine if they are legitimate or part of an ongoing attack.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems may be affected.
* Implement additional logging and monitoring for process execution events on Linux systems to enhance detection capabilities for similar threats in the future.


## Setup [_setup_274]

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


## Rule query [_rule_query_466]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and
process.name == "unmkinitramfs"
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

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



