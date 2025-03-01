---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-privilege-escalation-via-uid-int-max-bug-detected.html
---

# Potential Privilege Escalation via UID INT_MAX Bug Detected [prebuilt-rule-8-17-3-potential-privilege-escalation-via-uid-int-max-bug-detected]

This rule monitors for the execution of the systemd-run command by a user with a UID that is larger than the maximum allowed UID size (INT_MAX). Some older Linux versions were affected by a bug which allows user accounts with a UID greater than INT_MAX to escalate privileges by spawning a shell through systemd-run.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/paragonsec/status/1071152249529884674](https://twitter.com/paragonsec/status/1071152249529884674)
* [https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
* [https://gitlab.freedesktop.org/polkit/polkit/-/issues/74](https://gitlab.freedesktop.org/polkit/polkit/-/issues/74)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_899]

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


## Rule query [_rule_query_4949]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "ProcessRollup2") and
  process.name == "systemd-run" and process.args == "-t" and process.args_count >= 3 and user.id >= "1000000000"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



