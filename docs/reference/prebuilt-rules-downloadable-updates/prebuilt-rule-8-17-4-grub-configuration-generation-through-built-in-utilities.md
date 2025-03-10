---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-grub-configuration-generation-through-built-in-utilities.html
---

# GRUB Configuration Generation through Built-in Utilities [prebuilt-rule-8-17-4-grub-configuration-generation-through-built-in-utilities]

This rule detects the generation of a new GRUB configuration file using built-in Linux commands. The GRUB configuration file is used to configure the GRUB bootloader, which is responsible for loading the Linux kernel and initramfs image during the boot process. Attackers may use these built-in utilities to generate a new GRUB configuration file that includes malicious kernel parameters or boot options, which can be leveraged to maintain persistence on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4457]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GRUB Configuration Generation through Built-in Utilities**

GRUB, the Grand Unified Bootloader, is crucial for loading the Linux kernel during system startup. It uses configuration files to determine boot parameters. Adversaries may exploit utilities like `grub-mkconfig` to alter these files, embedding malicious parameters for persistence. The detection rule identifies suspicious executions of these utilities, especially when initiated by atypical parent processes, signaling potential misuse.

**Possible investigation steps**

* Review the process execution details to identify the parent process of the suspicious GRUB configuration utility execution. Check if the parent process is unusual or unexpected based on the query’s exclusion list.
* Examine the command-line arguments used in the execution of the GRUB configuration utility to identify any potentially malicious kernel parameters or boot options.
* Investigate the user account associated with the process execution to determine if it has the necessary privileges and if the activity aligns with the user’s typical behavior.
* Check the system’s recent changes or updates, especially those related to bootloader configurations, to identify any unauthorized modifications.
* Analyze system logs for any other suspicious activities or anomalies around the time of the GRUB configuration utility execution to gather additional context.

**False positive analysis**

* Routine system updates or maintenance tasks may trigger the rule when legitimate processes like package managers (e.g., pacman, dnf, yum) or system utilities (e.g., sudo) execute GRUB configuration commands. Users can mitigate this by adding these processes to the exception list in the rule configuration.
* Automated scripts or cron jobs that regularly update GRUB configurations for legitimate reasons might be flagged. To handle this, identify these scripts and add their parent process names or paths to the exclusion criteria.
* Custom administrative scripts that manage bootloader settings could also cause false positives. Review these scripts and, if verified as safe, include their parent process details in the rule’s exceptions.
* Some Linux distributions may have specific utilities or services that interact with GRUB as part of their normal operation. Investigate these utilities and consider excluding them if they are confirmed to be benign and necessary for system functionality.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious processes related to `grub-mkconfig`, `grub2-mkconfig`, or `update-grub` that were initiated by atypical parent processes.
* Review and restore the GRUB configuration file from a known good backup to ensure no malicious parameters are present.
* Conduct a thorough examination of the system for additional signs of compromise, focusing on persistence mechanisms and unauthorized changes to boot parameters.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement monitoring for future unauthorized executions of GRUB configuration utilities, ensuring alerts are generated for similar suspicious activities.
* Review and update access controls and permissions to restrict the execution of GRUB configuration utilities to authorized personnel only.


## Setup [_setup_1300]

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


## Rule query [_rule_query_5449]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.executable != null and process.name in ("grub-mkconfig", "grub2-mkconfig", "update-grub") and not (
  process.parent.name in ("run-parts", "sudo", "update-grub", "pacman", "dockerd", "dnf", "rpm", "yum") or
  process.parent.executable like~ (
    "/var/lib/dpkg/info/*", "/usr/lib/bootloader/grub2-efi/config", "/tmp/newroot/*", "/usr/lib/kernel/install.d/*"
  )
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



