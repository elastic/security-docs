---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/modification-of-dynamic-linker-preload-shared-object.html
---

# Modification of Dynamic Linker Preload Shared Object [modification-of-dynamic-linker-preload-shared-object]

Identifies modification of the dynamic linker preload shared object (ld.so.preload). Adversaries may execute malicious payloads by hijacking the dynamic linker used to load libraries.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang](https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_539]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification of Dynamic Linker Preload Shared Object**

The dynamic linker preload mechanism in Linux, via `/etc/ld.so.preload`, allows preloading of shared libraries, influencing how executables load dependencies. Adversaries exploit this by inserting malicious libraries, hijacking execution flow for privilege escalation. The detection rule monitors changes to this file, excluding benign processes, to identify unauthorized modifications indicative of such abuse.

**Possible investigation steps**

* Review the alert details to confirm the file path involved is /etc/ld.so.preload and verify the event action is one of the specified actions: updated, renamed, or file_rename_event.
* Identify the process responsible for the modification by examining the process.name field, ensuring it is not one of the excluded processes (wine or oneagentinstallaction).
* Investigate the process that triggered the alert by gathering additional context such as process ID, command line arguments, and parent process to understand its origin and purpose.
* Check the modification timestamp and correlate it with other system events or logs to identify any suspicious activity or patterns around the time of the modification.
* Analyze the contents of /etc/ld.so.preload to determine if any unauthorized or suspicious libraries have been added, and assess their potential impact on the system.
* Review user accounts and permissions associated with the process to determine if there has been any unauthorized access or privilege escalation attempt.
* If malicious activity is confirmed, isolate the affected system and follow incident response procedures to mitigate the threat and prevent further exploitation.

**False positive analysis**

* Legitimate software installations or updates may modify /etc/ld.so.preload. To handle this, monitor the process names associated with these activities and consider adding them to the exclusion list if they are verified as benign.
* System management tools like configuration management software might update /etc/ld.so.preload as part of routine operations. Identify these tools and exclude their process names from the detection rule to prevent false alerts.
* Custom scripts or administrative tasks executed by trusted users could inadvertently trigger the rule. Review these scripts and, if necessary, exclude their process names or user accounts from the detection criteria.
* Security agents or monitoring tools that interact with system files might cause false positives. Verify these tools' activities and exclude their process names if they are known to be safe and necessary for system operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate any suspicious processes that are not part of the baseline or known benign applications, especially those related to the modification of `/etc/ld.so.preload`.
* Restore the `/etc/ld.so.preload` file from a known good backup to ensure no malicious libraries are preloaded.
* Conduct a thorough review of recent system changes and installed packages to identify any unauthorized software or modifications that may have facilitated the attack.
* Escalate the incident to the security operations team for a deeper forensic analysis to determine the scope of the compromise and identify any additional affected systems.
* Implement additional monitoring on the affected system and similar environments to detect any further attempts to modify the dynamic linker preload file.
* Review and enhance access controls and permissions on critical system files like `/etc/ld.so.preload` to prevent unauthorized modifications in the future.


## Setup [_setup_352]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://docs/reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_580]

```js
host.os.type:linux and event.category:file and event.action:(file_rename_event or rename or renamed or updated) and
not event.type:deletion and file.path:/etc/ld.so.preload and
process.name:(* and not (oneagentinstallaction or passwd or wine))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



