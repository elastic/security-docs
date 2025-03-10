---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-apt-package-manager-execution.html
---

# Suspicious APT Package Manager Execution [prebuilt-rule-8-17-4-suspicious-apt-package-manager-execution]

Detects suspicious process events executed by the APT package manager, potentially indicating persistence through an APT backdoor. In Linux, APT (Advanced Package Tool) is a command-line utility used for handling packages on Debian-based systems, providing functions for installing, updating, upgrading, and removing software along with managing package repositories. Attackers can backdoor APT to gain persistence by injecting malicious code into scripts that APT runs, thereby ensuring continued unauthorized access or control each time APT is used for package management.

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

* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4435]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious APT Package Manager Execution**

The APT package manager is a vital tool for managing software on Debian-based Linux systems, handling tasks like installation and updates. Adversaries may exploit APT by embedding malicious scripts to maintain persistence and control. The detection rule identifies unusual shell or script executions initiated by APT, signaling potential backdoor activities, thus aiding in early threat detection and response.

**Possible investigation steps**

* Review the process execution details to identify the specific shell or script that was executed with APT as the parent process. Pay attention to the process names and arguments, such as "bash", "dash", "sh", etc., and the presence of the "-c" argument.
* Examine the command-line arguments and scripts executed by the suspicious process to determine if they contain any malicious or unexpected commands.
* Check the parent process details, specifically the APT process, to understand the context in which the shell or script was executed. This includes reviewing any recent package installations or updates that might have triggered the execution.
* Investigate the user account under which the suspicious process was executed to assess if it has been compromised or if it has elevated privileges that could be exploited.
* Correlate the event with other security logs or alerts from the same host to identify any additional indicators of compromise or related suspicious activities.
* Review the system’s package management logs to identify any recent changes or anomalies in package installations or updates that could be linked to the suspicious execution.

**False positive analysis**

* Legitimate administrative scripts executed by system administrators using APT may trigger the rule. To handle this, identify and document routine administrative tasks and create exceptions for these specific scripts or commands.
* Automated system maintenance scripts that use APT for updates or installations can be mistaken for suspicious activity. Review and whitelist these scripts by their specific command patterns or script names.
* Custom software deployment processes that involve APT and shell scripts might be flagged. Analyze these processes and exclude them by defining clear criteria for legitimate deployment activities.
* Security tools or monitoring solutions that interact with APT for scanning or auditing purposes may cause false positives. Verify these tools' operations and exclude their known benign processes from triggering the rule.
* Development environments where developers frequently use APT and shell scripts for testing and building software can lead to alerts. Establish a baseline of normal development activities and exclude these from the detection rule.

**Response and remediation**

* Isolate the affected host immediately to prevent further unauthorized access or lateral movement within the network.
* Terminate any suspicious processes identified in the alert, particularly those initiated by the APT package manager that match the query criteria.
* Conduct a thorough review of the APT configuration files and scripts to identify and remove any injected malicious code or unauthorized modifications.
* Restore the affected system from a known good backup if malicious modifications are extensive or if the integrity of the system cannot be assured.
* Update all system packages and apply security patches to mitigate vulnerabilities that may have been exploited by the adversary.
* Monitor the affected host and network for any signs of re-infection or further suspicious activity, focusing on the execution of shell scripts and unauthorized network connections.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_1278]

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


## Rule query [_rule_query_5427]

```js
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
   ) and not process.executable == "/usr/lib/venv-salt-minion/bin/python.original"
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and process.name : (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*",
     "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   )
  ] by process.parent.entity_id
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

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



