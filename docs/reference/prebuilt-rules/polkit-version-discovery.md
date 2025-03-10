---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/polkit-version-discovery.html
---

# Polkit Version Discovery [polkit-version-discovery]

This rule detects Polkit version discovery activity on Linux systems. Polkit version discovery can be an indication of an attacker attempting to exploit misconfigurations or vulnerabilities in the Polkit service.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_638]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Polkit Version Discovery**

Polkit, a system service in Linux, manages system-wide privileges, enabling non-privileged processes to communicate with privileged ones. Adversaries may exploit Polkit by discovering its version to identify vulnerabilities or misconfigurations. The detection rule identifies suspicious activities by monitoring specific command executions related to Polkit version checks, signaling potential reconnaissance efforts by attackers.

**Possible investigation steps**

* Review the process execution details to confirm the command used for Polkit version discovery, focusing on the process name and arguments such as "dnf", "rpm", "apt", or "pkaction".
* Check the user account associated with the process execution to determine if it is a legitimate user or potentially compromised.
* Investigate the host from which the command was executed to assess if it has a history of suspicious activities or if it is a high-value target.
* Correlate the event with other logs or alerts to identify if there are additional indicators of compromise or related reconnaissance activities.
* Evaluate the necessity and frequency of Polkit version checks in the environment to determine if this behavior is expected or anomalous.

**False positive analysis**

* Routine system updates or package management activities may trigger the rule when administrators use package managers like dnf, rpm, or apt to check for updates or verify installed packages. To mitigate this, create exceptions for known administrative scripts or user accounts that regularly perform these actions.
* Automated system monitoring tools that check software versions for compliance or inventory purposes might also cause false positives. Identify these tools and exclude their processes from triggering the rule.
* Developers or system administrators testing Polkit configurations or updates might execute version checks as part of their workflow. Consider excluding specific user accounts or process paths associated with development and testing environments.
* Security audits or vulnerability assessments conducted by internal teams may involve version checks as part of their procedures. Coordinate with these teams to whitelist their activities during scheduled assessments.

**Response and remediation**

* Isolate the affected system from the network to prevent potential lateral movement by the attacker.
* Terminate any suspicious processes identified in the alert, such as those involving the execution of Polkit version discovery commands.
* Conduct a thorough review of system logs and command history to identify any unauthorized access or further malicious activities.
* Apply any available security patches or updates to the Polkit service to address known vulnerabilities.
* Implement stricter access controls and monitoring on systems running Polkit to prevent unauthorized version checks and other reconnaissance activities.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Enhance detection capabilities by configuring alerts for similar reconnaissance activities across the network to ensure early detection of potential threats.


## Setup [_setup_406]

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


## Rule query [_rule_query_680]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and (
  (process.name == "dnf" and process.args == "dnf" and process.args == "info" and process.args == "polkit") or
  (process.name == "rpm" and process.args == "polkit") or
  (process.name == "apt" and process.args == "show" and process.args == "policykit-1") or
  (process.name == "pkaction" and process.args == "--version")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



