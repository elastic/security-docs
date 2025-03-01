---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-rpm-package-installed-by-unusual-parent-process.html
---

# RPM Package Installed by Unusual Parent Process [prebuilt-rule-8-17-4-rpm-package-installed-by-unusual-parent-process]

This rule leverages the new_terms rule type to identify the installation of RPM packages by an unusual parent process. RPM is a package management system used in Linux systems such as Red Hat, CentOS and Fedora. Attacks may backdoor RPM packages to gain initial access or install malicious RPM packages to maintain persistence.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4485]

**Triage and analysis**

[TBC: QUOTE]
**Investigating RPM Package Installed by Unusual Parent Process**

RPM is a package management system crucial for managing software on Linux distributions like Red Hat and CentOS. Adversaries may exploit RPM by installing backdoored or malicious packages to gain persistence or initial access. The detection rule identifies anomalies by flagging RPM installations initiated by atypical parent processes, which could indicate unauthorized or suspicious activity. This helps in early detection of potential threats by monitoring process execution patterns.

**Possible investigation steps**

* Review the parent process of the RPM installation to determine if it is a known and legitimate process. Investigate any unusual or unexpected parent processes that initiated the RPM command.
* Examine the command-line arguments used with the RPM process, specifically looking for the "-i" or "--install" flags, to confirm the installation action and gather more context about the package being installed.
* Check the timestamp of the event to correlate it with other activities on the system, such as user logins or other process executions, to identify any suspicious patterns or anomalies.
* Investigate the user account under which the RPM installation was executed to determine if it aligns with expected administrative activities or if it indicates potential unauthorized access.
* Analyze the network activity around the time of the RPM installation to identify any external connections that could suggest data exfiltration or communication with a command and control server.
* Review system logs and other security alerts from the same timeframe to identify any additional indicators of compromise or related suspicious activities.

**False positive analysis**

* System administrators or automated scripts may frequently install RPM packages as part of routine maintenance or updates. To manage this, create exceptions for known administrative accounts or specific scripts that regularly perform these actions.
* Some legitimate software deployment tools might use non-standard parent processes to install RPM packages. Identify and whitelist these tools to prevent unnecessary alerts.
* Development environments might trigger RPM installations through unusual parent processes during testing or software builds. Exclude these environments or specific processes from the rule to reduce false positives.
* Custom or third-party management tools that are not widely recognized might also cause alerts. Review and whitelist these tools if they are verified as safe and necessary for operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or further compromise.
* Terminate any suspicious processes related to the RPM installation that were initiated by unusual parent processes.
* Conduct a thorough review of the installed RPM packages to identify and remove any unauthorized or malicious software.
* Restore the system from a known good backup if malicious packages have been confirmed and system integrity is compromised.
* Update and patch the system to ensure all software is up-to-date, reducing the risk of exploitation through known vulnerabilities.
* Implement stricter access controls and monitoring on systems to prevent unauthorized RPM installations, focusing on unusual parent processes.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1323]

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


## Rule query [_rule_query_5477]

```js
host.os.type:linux and event.category:process and event.type:start and event.action:exec and process.name:rpm and
process.args:("-i" or "--install")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Installer Packages
    * ID: T1546.016
    * Reference URL: [https://attack.mitre.org/techniques/T1546/016/](https://attack.mitre.org/techniques/T1546/016/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Supply Chain Compromise
    * ID: T1195
    * Reference URL: [https://attack.mitre.org/techniques/T1195/](https://attack.mitre.org/techniques/T1195/)

* Sub-technique:

    * Name: Compromise Software Supply Chain
    * ID: T1195.002
    * Reference URL: [https://attack.mitre.org/techniques/T1195/002/](https://attack.mitre.org/techniques/T1195/002/)



