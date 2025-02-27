---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-dpkg-execution.html
---

# Unusual DPKG Execution [unusual-dpkg-execution]

This rule detects the execution of the DPKG command by processes not associated with the DPKG package manager. The DPKG command is used to install, remove, and manage Debian packages on a Linux system. Attackers can abuse the DPKG command to install malicious packages on a system.

**Rule type**: eql

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

## Investigation guide [_investigation_guide_1109]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual DPKG Execution**

DPKG is a core utility in Debian-based Linux systems for managing software packages. While essential for legitimate software management, adversaries can exploit DPKG to install or manipulate packages for malicious purposes, potentially gaining persistence or executing unauthorized code. The detection rule identifies anomalies by flagging DPKG executions initiated by unexpected processes, which may indicate unauthorized package management activities.

**Possible investigation steps**

* Review the process details to identify the unexpected process that initiated the DPKG execution. Pay attention to the process.executable field to understand which script or binary was executed.
* Examine the process.parent.name and process.parent.executable fields to determine the parent process that launched the DPKG command. This can provide insights into whether the execution was part of a legitimate process chain or potentially malicious.
* Investigate the process.session_leader.name and process.group_leader.name fields to understand the broader context of the session and group leaders involved in the execution. This can help identify if the execution was part of a larger, coordinated activity.
* Check the system logs and any available audit logs around the time of the alert to gather additional context on the activities occurring on the system. Look for any other suspicious or related events.
* Assess the system for any unauthorized or unexpected package installations or modifications that may have occurred as a result of the DPKG execution. This can help determine if the system has been compromised.

**False positive analysis**

* System maintenance scripts may trigger the rule if they execute DPKG commands outside of typical package management processes. To handle this, identify and whitelist these scripts by adding their parent process names or executables to the exception list.
* Automated software update tools, other than the ones specified in the rule, might cause false positives. Review the tools used in your environment and consider adding their executables to the exclusion criteria if they are verified as safe.
* Custom administrative scripts that manage packages could be flagged. Ensure these scripts are reviewed for legitimacy and then exclude their process names or paths from the rule to prevent unnecessary alerts.
* Development or testing environments where package manipulation is frequent might generate alerts. In such cases, consider creating environment-specific exceptions to reduce noise while maintaining security in production systems.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized package installations or potential lateral movement by the adversary.
* Terminate any suspicious processes identified as executing the DPKG command from unexpected sources to halt any ongoing malicious activities.
* Conduct a thorough review of recently installed or modified packages on the affected system to identify and remove any unauthorized or malicious software.
* Restore the system from a known good backup if malicious packages have been installed and cannot be safely removed without compromising system integrity.
* Update and patch the affected system to ensure all software is up-to-date, reducing the risk of exploitation through known vulnerabilities.
* Implement stricter access controls and monitoring on package management utilities to prevent unauthorized use, ensuring only trusted processes can execute DPKG commands.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_697]

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


## Rule query [_rule_query_1163]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.executable : "/var/lib/dpkg/info/*" and process.session_leader.name != null and
process.group_leader.name != null and not (
  process.parent.name in ("dpkg", "dpkg-reconfigure", "frontend") or
  process.session_leader.name == "dpkg" or
  process.group_leader.name == "dpkg" or
  process.parent.executable in ("/usr/share/debconf/frontend", "/usr/bin/unattended-upgrade")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Installer Packages
    * ID: T1546.016
    * Reference URL: [https://attack.mitre.org/techniques/T1546/016/](https://attack.mitre.org/techniques/T1546/016/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

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



