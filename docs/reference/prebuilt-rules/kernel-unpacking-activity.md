---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kernel-unpacking-activity.html
---

# Kernel Unpacking Activity [kernel-unpacking-activity]

This rule detects kernel unpacking activity through several built-in Linux utilities. Attackers may use these utilities to unpack kernel images and modules to search for vulnerabilities or to modify the kernel.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/declawing-pumakit](https://www.elastic.co/security-labs/declawing-pumakit)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_452]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Unpacking Activity**

Kernel unpacking involves using utilities to extract or inspect kernel images and modules, often for legitimate maintenance or updates. However, adversaries exploit this to identify vulnerabilities or alter the kernel for malicious purposes. The detection rule identifies suspicious unpacking by monitoring specific Linux utilities and command patterns, excluding benign processes like system updates, to flag potential threats.

**Possible investigation steps**

* Review the process details to identify the specific utility used for unpacking, such as "file", "unlzma", "gunzip", etc., and verify if the usage aligns with typical system maintenance activities.
* Examine the parent process name and arguments, especially those involving "/boot/*", to determine if the unpacking activity is part of a legitimate system operation or an unauthorized action.
* Check the user account associated with the process to assess if the activity was initiated by a legitimate user or an unauthorized entity.
* Investigate the timing of the event to see if it coincides with scheduled maintenance or updates, which might explain the unpacking activity.
* Look for any related alerts or logs that might indicate further suspicious behavior, such as attempts to modify kernel modules or other system files following the unpacking activity.
* Cross-reference the event with recent system updates or patches to rule out false positives related to legitimate system operations.

**False positive analysis**

* System updates and maintenance activities can trigger this rule when legitimate processes unpack kernel images. To manage this, exclude processes initiated by known update utilities like "mkinitramfs" from triggering alerts.
* Custom scripts or administrative tasks that involve unpacking kernel images for legitimate purposes may also cause false positives. Identify and whitelist these scripts or processes by their specific command patterns or parent process names.
* Backup or recovery operations that involve accessing or unpacking kernel files might be flagged. Review these operations and exclude them by specifying the responsible process names or arguments in the detection rule.
* Automated security tools that scan or analyze kernel images for compliance or vulnerability assessments can be mistaken for malicious activity. Exclude these tools by adding their process names to the exception list.

**Response and remediation**

* Isolate the affected system from the network to prevent potential lateral movement or further exploitation by the adversary.
* Terminate any suspicious processes identified by the detection rule, especially those involving the unpacking of kernel images or modules.
* Conduct a thorough review of the system’s kernel and module integrity using trusted tools to ensure no unauthorized modifications have been made.
* Restore the system from a known good backup if any unauthorized changes to the kernel or system files are detected.
* Update the system’s kernel and all related packages to the latest versions to mitigate any known vulnerabilities that could be exploited.
* Monitor the system for any recurring suspicious activity, focusing on the use of utilities and command patterns identified in the detection rule.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_288]

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


## Rule query [_rule_query_487]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
(process.parent.args like "/boot/*" or process.args like "/boot/*") and (
  (process.name in ("file", "unlzma", "gunzip", "unxz", "bunzip2", "unzstd", "unzip", "tar")) or
  (process.name == "grep" and process.args == "ELF") or
  (process.name in ("lzop", "lz4") and process.args in ("-d", "--decode"))
) and
not process.parent.name == "mkinitramfs"
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



