---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-chroot-container-escape-via-mount.html
---

# Potential Chroot Container Escape via Mount [potential-chroot-container-escape-via-mount]

Monitors for the execution of a file system mount followed by a chroot execution. Given enough permissions, a user within a container is capable of mounting the root file system of the host, and leveraging chroot to escape its containarized environment. This behavior pattern is very uncommon and should be investigated.

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

* [https://book.hacktricks.xyz/v/portugues-ht/linux-hardening/privilege-escalation/escaping-from-limited-bash](https://book.hacktricks.xyz/v/portugues-ht/linux-hardening/privilege-escalation/escaping-from-limited-bash)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Domain: Container
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_651]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Chroot Container Escape via Mount**

Chroot and mount are Linux utilities that can isolate processes and manage file systems, respectively. Adversaries may exploit these to escape containerized environments by mounting the host’s root file system and using chroot to change the root directory, gaining unauthorized access. The detection rule identifies this rare sequence by monitoring for mount and chroot executions within a short timeframe, signaling potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific host.id and process.parent.entity_id associated with the alert to understand which system and parent process are involved.
* Examine the process execution timeline to confirm the sequence of the mount and chroot commands, ensuring they occurred within the specified maxspan of 5 minutes.
* Investigate the process.args field for the mount command to determine the specific device or file system being targeted, especially focusing on any /dev/sd* entries that suggest attempts to access physical disks.
* Check the user permissions and roles associated with the process.parent.name (e.g., bash, dash, sh) to assess if the user had sufficient privileges to perform such operations.
* Analyze the broader context of the host.os.type to identify any recent changes or anomalies in the Linux environment that could have facilitated this behavior.
* Correlate with other security logs or alerts from the same host to identify any additional suspicious activities or patterns that might indicate a broader attack or compromise.

**False positive analysis**

* System maintenance scripts may trigger the rule if they involve mounting and chroot operations. Review scheduled tasks and scripts to identify legitimate use and consider excluding these specific processes from the rule.
* Backup or recovery operations that require mounting file systems and changing root directories can also cause false positives. Identify these operations and create exceptions for the associated processes or users.
* Development or testing environments where users frequently perform mount and chroot operations for legitimate purposes may trigger alerts. Evaluate the necessity of these actions and exclude known safe processes or users.
* Automated deployment tools that use mount and chroot as part of their setup routines can be mistaken for malicious activity. Verify the tools and their processes, then add them to an exclusion list if they are deemed safe.
* Custom scripts executed by trusted users that involve mount and chroot should be reviewed. If these scripts are part of regular operations, consider excluding them from the detection rule.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or potential lateral movement within the host system.
* Terminate any suspicious processes identified as executing the mount or chroot commands within the container to halt any ongoing escape attempts.
* Conduct a thorough review of the container’s permissions and configurations to ensure that only necessary privileges are granted, reducing the risk of similar exploits.
* Inspect the host system for any signs of compromise or unauthorized access, focusing on logs and system changes around the time of the detected activity.
* Restore the container from a known good backup if any unauthorized changes or compromises are detected, ensuring the environment is clean and secure.
* Update and patch the container and host systems to address any known vulnerabilities that could be exploited for privilege escalation or container escape.
* Escalate the incident to the security operations team for further analysis and to determine if additional monitoring or security measures are required to prevent future occurrences.


## Setup [_setup_415]

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

Session View uses process data collected by the Elastic Defend integration, but this data is not always collected by default. Session View is available on enterprise subscription for versions 8.3 and above.

**To confirm that Session View data is enabled:**

* Go to “Manage → Policies”, and edit one or more of your Elastic Defend integration policies.
* Select the” Policy settings” tab, then scroll down to the “Linux event collection” section near the bottom.
* Check the box for “Process events”, and turn on the “Include session data” toggle.
* If you want to include file and network alerts in Session View, check the boxes for “Network and File events”.
* If you want to enable terminal output capture, turn on the “Capture terminal output” toggle. For more information about the additional fields collected when this setting is enabled and the usage of Session View for Analysis refer to the [helper guide](docs-content://solutions/security/investigate/session-view.md).


## Rule query [_rule_query_693]

```js
sequence by host.id, process.parent.entity_id with maxspan=5m
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.name == "mount" and process.args : "/dev/sd*" and process.args_count >= 3 and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.name == "chroot"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)



