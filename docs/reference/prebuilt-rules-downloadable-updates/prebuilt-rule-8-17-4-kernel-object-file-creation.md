---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kernel-object-file-creation.html
---

# Kernel Object File Creation [prebuilt-rule-8-17-4-kernel-object-file-creation]

This rule detects the creation of a Linux kernel object file (.ko) on a system. Threat actors may leverage Linux kernel object files to load a rootkit or other type of malware on a system providing them with complete control and the ability to hide from security products.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.file-*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4463]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Object File Creation**

Kernel object files (.ko) are loadable modules that extend the functionality of the Linux kernel, often used for adding drivers or system features. Adversaries exploit this by loading malicious modules, such as rootkits, to gain control and evade detection. The detection rule identifies suspicious .ko file creation, excluding benign paths, to flag potential threats while minimizing false positives.

**Possible investigation steps**

* Review the file path of the created .ko file to determine if it is located in a suspicious or unusual directory that is not excluded by the rule, such as /var/tmp or /usr/local.
* Examine the process that created the .ko file by checking the process.executable and process.name fields to identify if it is a known legitimate process or potentially malicious.
* Investigate the parent process of the process that created the .ko file to understand the context of how the file was created and if it was initiated by a legitimate user action or a script.
* Check for any recent system changes or anomalies around the time of the .ko file creation, such as new user accounts, changes in system configurations, or other suspicious file activities.
* Look for any associated network activity from the host around the time of the .ko file creation to identify potential command and control communications or data exfiltration attempts.
* Correlate the alert with other security events or logs from the same host to identify any patterns or additional indicators of compromise that may suggest a broader attack campaign.

**False positive analysis**

* Kernel updates and system maintenance activities can generate .ko files in legitimate scenarios. Users should monitor for these activities and consider excluding paths related to official update processes.
* Custom kernel module development by developers or system administrators may trigger this rule. Establish a process to whitelist known development environments or specific user accounts involved in module creation.
* Automated system recovery tools, such as those using mkinitramfs, may create .ko files. Ensure these paths are excluded as indicated in the rule to prevent unnecessary alerts.
* Snap package installations might involve .ko file creation. Exclude the /snap/ directory to avoid false positives from legitimate package installations.
* Backup and restoration processes using tools like cpio can lead to .ko file creation. Verify these processes and exclude them if they are part of routine system operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes associated with the creation of the .ko file, especially those not originating from known benign paths.
* Remove the suspicious .ko file from the system to prevent it from being loaded into the kernel.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious components.
* Review system logs and audit trails to identify any unauthorized access or changes made around the time of the .ko file creation.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement additional monitoring and alerting for similar activities, ensuring that any future attempts to create or load unauthorized .ko files are promptly detected and addressed.


## Setup [_setup_1306]

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


## Rule query [_rule_query_5455]

```js
event.category:file and host.os.type:linux and event.type:creation and file.extension:ko and not (
  file.path:/var/tmp/mkinitramfs_* or process.executable:/snap/* or process.name:cpio
) and not file.path:/tmp/mkinitramfs*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



