---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-permission-modification-in-writable-directory.html
---

# File Permission Modification in Writable Directory [file-permission-modification-in-writable-directory]

Identifies file permission modifications in common writable directories by a non-root user. Adversaries often drop files or payloads into a writable directory and change permissions prior to execution.

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_334]

**Triage and analysis**

[TBC: QUOTE]
**Investigating File Permission Modification in Writable Directory**

In Linux environments, writable directories like /tmp or /var/tmp are often used for temporary file storage. Adversaries exploit these by modifying file permissions to execute malicious payloads. The detection rule identifies non-root users altering permissions in these directories using commands like chmod or chown, excluding benign processes, to flag potential threats. This helps in identifying unauthorized permission changes indicative of defense evasion tactics.

**Possible investigation steps**

* Review the process details to identify the non-root user who executed the permission modification command (chattr, chgrp, chmod, or chown) in the specified writable directories (/dev/shm, /tmp, or /var/tmp).
* Examine the parent process of the detected command to determine if it is associated with any known malicious activity or if it deviates from typical user behavior, ensuring it is not one of the excluded benign processes (apt-key, update-motd-updates-available, apt-get).
* Investigate the specific file or directory whose permissions were altered to assess its legitimacy and check for any associated suspicious files or payloads.
* Analyze recent activities by the identified user to detect any other anomalous behavior or unauthorized access attempts that could indicate a broader compromise.
* Cross-reference the event with other security logs and alerts to identify any correlated incidents or patterns that might suggest a coordinated attack or persistent threat.

**False positive analysis**

* System updates and maintenance scripts may trigger permission changes in writable directories. Exclude processes like apt-key, update-motd-updates-available, and apt-get to reduce noise from legitimate system activities.
* Development and testing environments often involve frequent permission changes by non-root users. Consider excluding specific user accounts or processes known to be part of regular development workflows.
* Automated backup or synchronization tools might modify file permissions as part of their operations. Identify and exclude these tools if they are verified to be non-threatening.
* Custom scripts or applications that require permission changes for functionality should be reviewed and, if deemed safe, added to an exception list to prevent false alerts.
* Regularly review and update the exclusion list to ensure it reflects current operational practices and does not inadvertently allow malicious activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified in the alert that are associated with unauthorized permission changes.
* Revert any unauthorized file permission changes in the writable directories to their original state to prevent execution of malicious payloads.
* Conduct a thorough scan of the affected directories (/dev/shm, /tmp, /var/tmp) for any malicious files or payloads and remove them.
* Review user accounts and permissions to ensure that only authorized users have access to modify file permissions in sensitive directories.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for file permission changes in writable directories to detect similar threats in the future.


## Setup [_setup_208]

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


## Rule query [_rule_query_353]

```js
host.os.type:linux and event.category:process and event.type:start and
process.name:(chattr or chgrp or chmod or chown) and process.working_directory:(/dev/shm or /tmp or /var/tmp) and
not process.parent.name:(
  apt-key or update-motd-updates-available or apt-get or java or pilot or PassengerAgent or nginx
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)



