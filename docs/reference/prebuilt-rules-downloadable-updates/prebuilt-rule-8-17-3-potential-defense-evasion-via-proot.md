---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-defense-evasion-via-proot.html
---

# Potential Defense Evasion via PRoot [prebuilt-rule-8-17-3-potential-defense-evasion-via-proot]

Identifies the execution of the PRoot utility, an open-source tool for user-space implementation of chroot, mount --bind, and binfmt_misc. Adversaries can leverage an open-source tool PRoot to expand the scope of their operations to multiple Linux distributions and simplify their necessary efforts. In a normal threat scenario, the scope of an attack is limited by the varying configurations of each Linux distribution. With PRoot, it provides an attacker with a consistent operational environment across different Linux distributions, such as Ubuntu, Fedora, and Alpine. PRoot also provides emulation capabilities that allow for malware built on other architectures, such as ARM, to be run.The post-exploitation technique called bring your own filesystem (BYOF), can be used by the threat actors to execute malicious payload or elevate privileges or perform network scans or orchestrate another attack on the environment. Although PRoot was originally not developed with malicious intent it can be easily tuned to work for one.

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

* [https://proot-me.github.io/](https://proot-me.github.io/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_842]

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


## Rule query [_rule_query_4885]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name == "proot"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Exploitation for Defense Evasion
    * ID: T1211
    * Reference URL: [https://attack.mitre.org/techniques/T1211/](https://attack.mitre.org/techniques/T1211/)



