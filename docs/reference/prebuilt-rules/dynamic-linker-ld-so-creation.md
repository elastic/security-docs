---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/dynamic-linker-ld-so-creation.html
---

# Dynamic Linker (ld.so) Creation [dynamic-linker-ld-so-creation]

This rule detects the creation of the dynamic linker (ld.so) file. The dynamic linker is used to load shared libraries needed by an executable. Attackers may attempt to replace the dynamic linker with a malicious version to execute arbitrary code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Defense Evasion
* Tactic: Execution
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_280]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Dynamic Linker (ld.so) Creation**

The dynamic linker, ld.so, is crucial in Linux environments for loading shared libraries required by executables. Adversaries may exploit this by replacing it with a malicious version to execute unauthorized code, achieving persistence or evading defenses. The detection rule identifies suspicious creation of ld.so files, excluding benign processes, to flag potential threats.

**Possible investigation steps**

* Review the process that triggered the alert by examining the process.executable field to understand which application attempted to create the ld.so file.
* Check the process.name field to ensure the process is not one of the benign processes listed in the exclusion criteria, such as "dockerd", "yum", "dnf", "microdnf", or "pacman".
* Investigate the file.path to confirm the location of the newly created ld.so file and verify if it matches any of the specified directories like "/lib", "/lib64", "/usr/lib", or "/usr/lib64".
* Analyze the parent process of the suspicious executable to determine if it was initiated by a legitimate or potentially malicious source.
* Look for any recent changes or anomalies in the system logs around the time of the file creation event to identify any related suspicious activities.
* Cross-reference the event with other security tools or logs, such as Elastic Defend or SentinelOne, to gather additional context or corroborating evidence of malicious activity.
* Assess the risk and impact of the event by considering the system’s role and the potential consequences of a compromised dynamic linker on that system.

**False positive analysis**

* Package managers like yum, dnf, microdnf, and pacman can trigger false positives when they update or install packages that involve the dynamic linker. These processes are already excluded in the rule, but ensure any custom package managers or scripts are also considered for exclusion.
* Container management tools such as dockerd may create or modify ld.so files during container operations. If you use other container tools, consider adding them to the exclusion list to prevent false positives.
* System updates or maintenance scripts that involve library updates might create ld.so files. Review these scripts and add them to the exclusion list if they are verified as non-threatening.
* Custom administrative scripts or automation tools that interact with shared libraries could inadvertently trigger the rule. Identify these scripts and exclude them if they are part of regular, secure operations.
* Development environments where ld.so files are frequently created or modified during testing and compilation processes may need specific exclusions for development tools or environments to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Verify the integrity of the dynamic linker (ld.so) on the affected system by comparing it with a known good version from a trusted source or repository.
* If the dynamic linker has been tampered with, replace it with the verified version and ensure all system binaries are intact.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malicious files or processes.
* Review system logs and the process creation history to identify the source of the unauthorized ld.so creation and any associated malicious activity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems are affected.
* Implement additional monitoring and alerting for similar suspicious activities, such as unauthorized file creations in critical system directories, to enhance future detection capabilities.


## Setup [_setup_180]

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


## Rule query [_rule_query_292]

```js
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.path like~ ("/lib/ld-linux*.so*", "/lib64/ld-linux*.so*", "/usr/lib/ld-linux*.so*", "/usr/lib64/ld-linux*.so*") and
not process.name in ("dockerd", "yum", "dnf", "microdnf", "pacman")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

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

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



