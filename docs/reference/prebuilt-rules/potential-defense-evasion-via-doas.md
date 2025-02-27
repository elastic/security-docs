---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-defense-evasion-via-doas.html
---

# Potential Defense Evasion via Doas [potential-defense-evasion-via-doas]

This rule detects the creation or rename of the Doas configuration file on a Linux system. Adversaries may create or modify the Doas configuration file to elevate privileges and execute commands as other users while attempting to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://wiki.archlinux.org/title/Doas](https://wiki.archlinux.org/title/Doas)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_672]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Defense Evasion via Doas**

Doas is a command-line utility on Linux systems that allows users to execute commands as another user, typically with elevated privileges. Adversaries may exploit this by altering the Doas configuration file to gain unauthorized access or escalate privileges, bypassing security measures. The detection rule identifies suspicious activities by monitoring changes to the Doas configuration file, signaling potential misuse aimed at evading defenses.

**Possible investigation steps**

* Review the alert details to confirm the file path involved is "/etc/doas.conf" and the event type is not "deletion", as specified in the query.
* Check the timestamp of the alert to determine when the configuration file was created or modified, and correlate this with any known scheduled changes or maintenance activities.
* Investigate the user account associated with the event to determine if they have legitimate reasons to modify the Doas configuration file, and verify their access permissions.
* Examine system logs and command history around the time of the alert to identify any suspicious activities or commands executed by the user.
* Assess the current Doas configuration file for unauthorized changes or entries that could indicate privilege escalation attempts.
* Cross-reference the alert with other security events or alerts from the same host to identify potential patterns or related activities that could suggest a broader attack.

**False positive analysis**

* Routine administrative updates to the Doas configuration file can trigger alerts. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for legitimate updates.
* Automated configuration management tools may modify the Doas configuration file as part of their normal operation. Identify these tools and exclude their activities from triggering alerts by specifying their process names or user accounts.
* System backups or restoration processes might involve creating or renaming the Doas configuration file. Exclude these processes by identifying the backup software and adding it to the exception list.
* Development or testing environments where frequent changes to the Doas configuration file are expected can generate false positives. Consider excluding these environments from monitoring or adjusting the rule to account for their unique activity patterns.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Review and revert any unauthorized changes to the Doas configuration file located at /etc/doas.conf to its last known good state.
* Conduct a thorough audit of user accounts and permissions on the affected system to identify and remove any unauthorized accounts or privilege escalations.
* Implement additional monitoring on the affected system to detect any further attempts to modify the Doas configuration file or other critical system files.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat has spread to other systems.
* Apply patches and updates to the affected system to address any vulnerabilities that may have been exploited by the adversary.
* Review and enhance access controls and authentication mechanisms to prevent unauthorized privilege escalation attempts in the future.


## Setup [_setup_430]

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


## Rule query [_rule_query_712]

```js
file where host.os.type == "linux" and event.type != "deletion" and file.path == "/etc/doas.conf"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)



