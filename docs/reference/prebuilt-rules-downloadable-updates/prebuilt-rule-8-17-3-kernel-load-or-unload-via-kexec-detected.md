---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-kernel-load-or-unload-via-kexec-detected.html
---

# Kernel Load or Unload via Kexec Detected [prebuilt-rule-8-17-3-kernel-load-or-unload-via-kexec-detected]

This detection rule identifies the usage of kexec, helping to uncover unauthorized kernel replacements and potential compromise of the system’s integrity. Kexec is a Linux feature that enables the loading and execution of a different kernel without going through the typical boot process. Malicious actors can abuse kexec to bypass security measures, escalate privileges, establish persistence or hide their activities by loading a malicious kernel, enabling them to tamper with the system’s trusted state, allowing e.g. a VM Escape.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.crowdstrike.com/blog/venom-vulnerability-details/](https://www.crowdstrike.com/blog/venom-vulnerability-details/)
* [https://www.makeuseof.com/what-is-venom-vulnerability/](https://www.makeuseof.com/what-is-venom-vulnerability/)
* [https://madaidans-insecurities.github.io/guides/linux-hardening.html](https://madaidans-insecurities.github.io/guides/linux-hardening.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_900]

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


## Rule query [_rule_query_4950]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.name == "kexec" and process.args in ("--exec", "-e", "--load", "-l", "--unload", "-u") and
  not process.parent.name in ("kdumpctl", "unload.sh")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify System Image
    * ID: T1601
    * Reference URL: [https://attack.mitre.org/techniques/T1601/](https://attack.mitre.org/techniques/T1601/)

* Sub-technique:

    * Name: Patch System Image
    * ID: T1601.001
    * Reference URL: [https://attack.mitre.org/techniques/T1601/001/](https://attack.mitre.org/techniques/T1601/001/)



