---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-memory-swap-modification.html
---

# Memory Swap Modification [prebuilt-rule-8-17-3-memory-swap-modification]

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

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_874]

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


## Rule query [_rule_query_4921]

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
)
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



