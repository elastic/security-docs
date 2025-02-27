---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-boot-file-copy.html
---

# Boot File Copy [prebuilt-rule-8-17-4-boot-file-copy]

This rule detects the process of copying or moving files from or to the `/boot` directory on Linux systems. The `/boot` directory contains files that are essential for the system to boot, such as the kernel and initramfs images. Attackers may copy or move files to the `/boot` directory to modify the boot process, which can be leveraged to maintain access to the system.

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

## Investigation guide [_investigation_guide_4439]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Boot File Copy**

The `/boot` directory in Linux systems is crucial for storing files necessary for booting, such as the kernel. Adversaries may exploit this by copying or moving files to alter the boot process, potentially gaining persistent access. The *Boot File Copy* detection rule identifies suspicious file operations in this directory, excluding legitimate processes, to flag potential unauthorized modifications.

**Possible investigation steps**

* Review the process details to identify the specific file operation by examining the process name and arguments, particularly focusing on the use of *cp* or *mv* commands with paths involving */boot/**.
* Investigate the parent process executable and name to determine if the operation was initiated by a known legitimate process or script, ensuring it is not one of the excluded processes like *update-initramfs* or *grub-mkconfig*.
* Check the user account associated with the process to assess whether it is a privileged account and if the activity aligns with typical user behavior.
* Analyze recent system logs and audit records for any other suspicious activities or anomalies around the time of the alert to identify potential patterns or related events.
* Verify the integrity and authenticity of the files in the /boot directory to ensure no unauthorized modifications have been made, focusing on critical files like the kernel and initramfs images.
* If possible, correlate the alert with other data sources such as Elastic Endgame or Crowdstrike to gather additional context and confirm whether this is part of a broader attack pattern.

**False positive analysis**

* System updates and maintenance tasks often involve legitimate processes that interact with the /boot directory. Processes like update-initramfs, dracut, and grub-mkconfig are common during these operations. Users can exclude these processes by adding them to the exception list in the detection rule.
* Custom scripts or administrative tasks that require copying or moving files to the /boot directory may trigger false positives. Identify these scripts and add their parent process names or paths to the exclusion criteria.
* Package management operations, such as those involving dpkg or rpm, may also interact with the /boot directory. Exclude paths like /var/lib/dpkg/info/* and /var/tmp/rpm-tmp.* to prevent these from being flagged.
* Temporary system recovery or installation processes might use directories like /tmp/newroot. Exclude these paths to avoid unnecessary alerts during legitimate recovery operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those involving unauthorized *cp* or *mv* operations in the /boot directory.
* Conduct a thorough review of the /boot directory to identify and remove any unauthorized files or modifications. Restore any altered files from a known good backup if necessary.
* Check for any unauthorized changes to boot configuration files, such as GRUB or LILO, and restore them to their original state.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar systems to detect any further unauthorized access attempts or modifications.
* Review and update access controls and permissions for the /boot directory to ensure only authorized processes and users can make changes.


## Setup [_setup_1282]

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


## Rule query [_rule_query_5431]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and
process.name in ("cp", "mv") and process.parent.executable != null and process.args like~ "/boot/*" and not (
  process.parent.name in ("update-initramfs", "dracut", "grub-mkconfig", "shim-install", "sudo", "activate-theme", "update-grub-gfxpayload", "grub-pc.postinst") or
  process.parent.executable like~ ("/usr/lib/kernel/install.d/*", "/tmp/newroot/*", "/var/lib/dpkg/info/*") or
  process.parent.args like~ ("/usr/bin/mkinitcpio", "/var/tmp/rpm-tmp.*")
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



