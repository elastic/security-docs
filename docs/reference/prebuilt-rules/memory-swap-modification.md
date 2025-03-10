---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/memory-swap-modification.html
---

# Memory Swap Modification [memory-swap-modification]

This rule detects memory swap modification events on Linux systems. Memory swap modification can be used to manipulate the system’s memory and potentially impact the system’s performance. This behavior is commonly observed in malware that deploys miner software such as XMRig.

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
* Tactic: Impact
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_500]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Memory Swap Modification**

Memory swap in Linux systems manages RAM by moving inactive pages to disk, freeing up memory for active processes. Adversaries exploit this by altering swap settings to degrade performance or deploy resource-intensive malware like cryptominers. The detection rule identifies suspicious activities by monitoring processes that modify swap settings or execute related commands, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the process details to identify the parent process using the field process.parent.executable. This can help determine if the swap modification was initiated by a legitimate or suspicious parent process.
* Examine the command line arguments captured in process.command_line to understand the specific changes made to swap settings, such as modifications to vm.swappiness.
* Check the user account associated with the process to determine if the action was performed by a privileged or unauthorized user.
* Investigate any recent system performance issues or anomalies that could be linked to swap modifications, such as increased CPU or memory usage.
* Correlate the event with other security alerts or logs to identify if this activity is part of a larger pattern of suspicious behavior, such as the presence of cryptomining software like XMRig.
* Assess the system for any unauthorized software installations or configurations that could indicate a compromise, focusing on resource-intensive applications.

**False positive analysis**

* System administrators may frequently modify swap settings during routine maintenance or performance tuning. To handle this, create exceptions for known administrator accounts or specific maintenance scripts.
* Automated configuration management tools like Ansible or Puppet might execute commands that alter swap settings. Identify these tools and exclude their processes from triggering alerts.
* Some legitimate applications may adjust swap settings to optimize their performance. Monitor and whitelist these applications to prevent unnecessary alerts.
* Development environments often experiment with system settings, including swap configurations. Consider excluding processes from known development environments or specific user accounts associated with development activities.
* Scheduled tasks or cron jobs might include swap modification commands for system optimization. Review and whitelist these tasks if they are verified as non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or impact of the potential malware.
* Terminate any suspicious processes identified by the detection rule, such as those involving "swapon", "swapoff", or unauthorized modifications to "vm.swappiness".
* Conduct a thorough scan of the isolated system using updated antivirus or anti-malware tools to identify and remove any malicious software, particularly cryptominers like XMRig.
* Review and restore swap settings to their default or secure configurations to ensure system stability and performance.
* Implement monitoring for any further unauthorized changes to swap settings or related processes to detect and respond to similar threats promptly.
* Escalate the incident to the security operations team for a detailed forensic analysis to understand the scope and origin of the attack.
* Update system and security patches to close any vulnerabilities that may have been exploited by the adversary.


## Setup [_setup_325]

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
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead.

For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md). - Click "Save and Continue". - To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts.

For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_539]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.parent.executable != null and
process.name in ("swapon", "swapoff") or (
  process.command_line like ("*vm.swappiness*", "*/proc/sys/vm/swappiness*") and (
    (process.name == "sysctl" and process.args like ("*-w*", "*--write*", "*=*")) or
    (
      process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and
      process.command_line like "*echo *"
    )
  )
) and
not process.parent.name in ("lynis", "systemd", "end-zram-swapping", "SyxsenseResponder", "tuned", "platform-python", "timeout")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Resource Hijacking
    * ID: T1496
    * Reference URL: [https://attack.mitre.org/techniques/T1496/](https://attack.mitre.org/techniques/T1496/)

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



