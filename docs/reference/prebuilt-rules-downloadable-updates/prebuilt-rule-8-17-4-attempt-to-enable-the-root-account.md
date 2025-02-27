---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-enable-the-root-account.html
---

# Attempt to Enable the Root Account [prebuilt-rule-8-17-4-attempt-to-enable-the-root-account]

Identifies attempts to enable the root account using the dsenableroot command. This command may be abused by adversaries for persistence, as the root account is disabled by default.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://ss64.com/osx/dsenableroot.html](https://ss64.com/osx/dsenableroot.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4590]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Enable the Root Account**

In macOS environments, the root account is typically disabled to enhance security. However, adversaries may attempt to enable it using the `dsenableroot` command to gain persistent, elevated access. The detection rule identifies such attempts by monitoring process events for the execution of `dsenableroot` without the disable flag, indicating potential misuse for persistence.

**Possible investigation steps**

* Review the process event logs to confirm the execution of the dsenableroot command without the disable flag, as indicated by the absence of process.args:"-d".
* Identify the user account associated with the process event to determine if the action was initiated by a legitimate user or a potential adversary.
* Check for any recent changes in user account permissions or configurations that might indicate unauthorized access or privilege escalation.
* Investigate any other suspicious activities or process executions around the same time as the dsenableroot command to identify potential lateral movement or further persistence mechanisms.
* Correlate the event with other security alerts or logs from the same host to assess if this is part of a broader attack campaign.

**False positive analysis**

* System administrators may legitimately enable the root account for maintenance or troubleshooting. To handle this, create exceptions for known administrator accounts or specific maintenance windows.
* Automated scripts or management tools might use the dsenableroot command as part of their operations. Identify these tools and exclude their process signatures from triggering alerts.
* Educational or testing environments may require enabling the root account for instructional purposes. Implement exclusions for these environments by tagging relevant systems or user accounts.
* Ensure that any exclusion rules are regularly reviewed and updated to reflect changes in administrative practices or tool usage to maintain security integrity.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent any potential lateral movement by the adversary.
* Terminate any unauthorized processes associated with the `dsenableroot` command to halt further misuse of elevated privileges.
* Review system logs and user activity to identify any unauthorized changes or access that occurred after the root account was enabled.
* Reset the root account password and disable the root account to prevent further unauthorized access.
* Conduct a thorough scan of the system for any additional signs of compromise or persistence mechanisms that may have been installed.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for any future attempts to enable the root account, ensuring rapid detection and response.


## Setup [_setup_1422]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5582]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:dsenableroot and not process.args:"-d"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



