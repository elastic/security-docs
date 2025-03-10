---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kernel-module-removal.html
---

# Kernel Module Removal [kernel-module-removal]

Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.

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

* [http://man7.org/linux/man-pages/man8/modprobe.8.html](http://man7.org/linux/man-pages/man8/modprobe.8.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_449]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Module Removal**

Kernel modules dynamically extend a Linux kernel’s capabilities without rebooting. Adversaries may exploit this by removing modules to disable security features or hide malicious activities. The detection rule identifies suspicious module removal attempts by monitoring processes like `rmmod` or `modprobe` with removal arguments, especially when initiated by common shell environments, indicating potential defense evasion tactics.

**Possible investigation steps**

* Review the process details to confirm the execution of `rmmod` or `modprobe` with removal arguments. Check the command line arguments to ensure they match the suspicious activity criteria.
* Identify the parent process of the suspicious activity, focusing on shell environments like `sudo`, `bash`, `dash`, `ash`, `sh`, `tcsh`, `csh`, `zsh`, `ksh`, or `fish`, to understand the context in which the module removal was initiated.
* Investigate the user account associated with the process to determine if the activity aligns with expected behavior or if it indicates potential unauthorized access.
* Check system logs and audit logs for any preceding or subsequent suspicious activities that might correlate with the module removal attempt, such as privilege escalation or other defense evasion tactics.
* Assess the impact of the module removal on system security features and functionality, and determine if any critical security modules were targeted.
* Review recent changes or updates to the system that might explain the module removal, such as legitimate maintenance or updates, to rule out false positives.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators use `rmmod` or `modprobe` for legitimate maintenance. To handle this, create exceptions for specific user accounts or scripts known to perform these tasks regularly.
* Automated scripts or configuration management tools that manage kernel modules might cause false positives. Identify these tools and exclude their processes from the rule to prevent unnecessary alerts.
* Some Linux distributions or custom setups might use shell scripts that invoke `rmmod` or `modprobe` during system updates or package installations. Monitor these activities and whitelist the associated parent processes if they are verified as non-threatening.
* Development environments where kernel module testing is frequent can generate alerts. Exclude specific development machines or user accounts involved in module testing to reduce noise.
* Security tools that perform regular checks or updates on kernel modules might inadvertently trigger the rule. Verify these tools and add them to the exception list to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Terminate any suspicious processes identified as attempting to remove kernel modules, such as those initiated by `rmmod` or `modprobe` with removal arguments.
* Conduct a thorough review of user accounts and privileges on the affected system to ensure no unauthorized access or privilege escalation has occurred.
* Restore any disabled security features or kernel modules to their original state to ensure the system’s defenses are intact.
* Analyze system logs and audit trails to identify any additional indicators of compromise or related malicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement enhanced monitoring and alerting for similar activities across the network to detect and respond to future attempts promptly.


## Setup [_setup_285]

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


## Rule query [_rule_query_484]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    process.name == "rmmod" or
    (process.name == "modprobe" and process.args in ("--remove", "-r"))
  ) and
  process.parent.name in ("sudo", "bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)



