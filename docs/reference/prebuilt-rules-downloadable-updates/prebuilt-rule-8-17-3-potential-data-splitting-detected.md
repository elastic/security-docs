---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-data-splitting-detected.html
---

# Potential Data Splitting Detected [prebuilt-rule-8-17-3-potential-data-splitting-detected]

This rule looks for the usage of common data splitting utilities with specific arguments that indicate data splitting for exfiltration on Linux systems. Data splitting is a technique used by adversaries to split data into smaller parts to avoid detection and exfiltrate data.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
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
* Tactic: Exfiltration
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_873]

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


## Rule query [_rule_query_4920]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name == "dd" and process.args like "bs=*" and process.args like "if=*") or
    (
      process.name in ("split", "rsplit") and
      (
        (process.args == "-b" or process.args like "--bytes*") or
        (process.args == "-C" or process.args like "--line-bytes*")
      )
    )
  ) and
  not (
    process.parent.name in ("apport", "overlayroot") or
    process.args like (
      "if=/tmp/nvim*", "if=/boot/*", "if=/dev/random", "if=/dev/urandom", "/dev/mapper/*",
      "if=*.iso", "of=/dev/stdout", "if=/dev/zero", "if=/dev/sda", "/proc/sys/kernel/*"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



