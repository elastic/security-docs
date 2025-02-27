---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dpkg-package-installed-by-unusual-parent-process.html
---

# DPKG Package Installed by Unusual Parent Process [prebuilt-rule-8-17-4-dpkg-package-installed-by-unusual-parent-process]

This rule detects the installation of a Debian package (dpkg) by an unusual parent process. The dpkg command is used to install, remove, and manage Debian packages on a Linux system. Attackers can abuse the dpkg command to install malicious packages on a system.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.makeuseof.com/how-deb-packages-are-backdoored-how-to-detect-it/](https://www.makeuseof.com/how-deb-packages-are-backdoored-how-to-detect-it/)

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

## Investigation guide [_investigation_guide_4446]

**Triage and analysis**

[TBC: QUOTE]
**Investigating DPKG Package Installed by Unusual Parent Process**

DPKG is a core utility for managing Debian packages on Linux systems, crucial for software installation and maintenance. Adversaries may exploit DPKG to install malicious packages, leveraging unusual parent processes to evade detection. The detection rule identifies such anomalies by monitoring DPKG executions initiated by atypical parent processes, signaling potential unauthorized package installations.

**Possible investigation steps**

* Review the process tree to identify the parent process of the dpkg execution. Determine if the parent process is legitimate or unusual for package installations.
* Examine the command-line arguments used with the dpkg command, specifically looking for the "-i" or "--install" flags, to understand what package was being installed.
* Check the source and integrity of the package being installed to ensure it is from a trusted repository or source.
* Investigate the user account under which the dpkg command was executed to determine if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Correlate the event with other logs or alerts around the same timeframe to identify any related suspicious activities or patterns.
* Assess the system for any signs of compromise or unauthorized changes following the package installation.

**False positive analysis**

* System updates or maintenance scripts may trigger the rule when legitimate administrative tools or scripts use dpkg to install updates. To handle this, identify and whitelist known maintenance scripts or processes that regularly perform package installations.
* Automated deployment tools like Ansible or Puppet might use dpkg for software deployment, leading to false positives. Exclude these tools by adding their process names to an exception list if they are part of your standard operations.
* Custom internal applications or scripts that manage software installations could also cause alerts. Review these applications and, if verified as safe, configure exceptions for their parent processes.
* Developers or system administrators using dpkg for testing or development purposes might inadvertently trigger the rule. Establish a policy for such activities and exclude known development environments or user accounts from triggering alerts.
* Backup or recovery operations that reinstall packages as part of their process can be mistaken for malicious activity. Identify these operations and exclude their associated processes from the rule.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized package installations or lateral movement by the adversary.
* Terminate the dpkg process if it is still running to stop any ongoing malicious package installation.
* Identify and remove any suspicious or unauthorized packages installed by the dpkg command using the package management tools available on the system.
* Conduct a thorough review of the system’s package installation logs and history to identify any other potentially malicious packages or unusual installation activities.
* Restore the system from a known good backup if malicious packages have altered critical system components or configurations.
* Implement stricter access controls and monitoring on systems to prevent unauthorized use of package management utilities by non-administrative users or processes.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected, ensuring a coordinated response to the threat.


## Setup [_setup_1289]

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


## Rule query [_rule_query_5438]

```js
host.os.type:linux and event.category:process and event.type:start and event.action:exec and process.name:dpkg and
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



