---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-chroot-container-escape-via-mount.html
---

# Potential Chroot Container Escape via Mount [prebuilt-rule-8-17-3-potential-chroot-container-escape-via-mount]

Monitors for the execution of a file system mount followed by a chroot execution. Given enough permissions, a user within a container is capable of mounting the root file system of the host, and leveraging chroot to escape its containarized environment. This behavior pattern is very uncommon and should be investigated.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://book.hacktricks.xyz/v/portugues-ht/linux-hardening/privilege-escalation/escaping-from-limited-bash](https://book.hacktricks.xyz/v/portugues-ht/linux-hardening/privilege-escalation/escaping-from-limited-bash)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Domain: Container
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_898]

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

Session View uses process data collected by the Elastic Defend integration, but this data is not always collected by default. Session View is available on enterprise subscription for versions 8.3 and above.

**To confirm that Session View data is enabled:**

* Go to “Manage → Policies”, and edit one or more of your Elastic Defend integration policies.
* Select the” Policy settings” tab, then scroll down to the “Linux event collection” section near the bottom.
* Check the box for “Process events”, and turn on the “Include session data” toggle.
* If you want to include file and network alerts in Session View, check the boxes for “Network and File events”.
* If you want to enable terminal output capture, turn on the “Capture terminal output” toggle. For more information about the additional fields collected when this setting is enabled and the usage of Session View for Analysis refer to the [helper guide](docs-content://solutions/security/investigate/session-view.md).


## Rule query [_rule_query_4948]

```js
sequence by host.id, process.parent.entity_id with maxspan=5m
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.name == "mount" and process.args : "/dev/sd*" and process.args_count >= 3 and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.name == "chroot"]
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



