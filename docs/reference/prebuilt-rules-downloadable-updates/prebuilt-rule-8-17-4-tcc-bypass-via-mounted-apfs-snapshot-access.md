---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-tcc-bypass-via-mounted-apfs-snapshot-access.html
---

# TCC Bypass via Mounted APFS Snapshot Access [prebuilt-rule-8-17-4-tcc-bypass-via-mounted-apfs-snapshot-access]

Identifies the use of the mount_apfs command to mount the entire file system through Apple File System (APFS) snapshots as read-only and with the noowners flag set. This action enables the adversary to access almost any file in the file system, including all user data and files protected by Apple’s privacy framework (TCC).

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://theevilbit.github.io/posts/cve_2020_9771/](https://theevilbit.github.io/posts/cve_2020_9771/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4565]

**Triage and analysis**

[TBC: QUOTE]
**Investigating TCC Bypass via Mounted APFS Snapshot Access**

Apple’s TCC framework safeguards user data by controlling app access to sensitive files. Adversaries exploit APFS snapshots, mounting them with specific flags to bypass these controls, gaining unauthorized access to protected data. The detection rule identifies this misuse by monitoring the execution of the `mount_apfs` command with parameters indicative of such bypass attempts, flagging potential security breaches.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the `mount_apfs` command with the specific arguments `/System/Volumes/Data` and `noowners` to verify the alert’s accuracy.
* Investigate the user account associated with the process execution to determine if the activity aligns with expected behavior or if it indicates potential unauthorized access.
* Examine the timeline of events leading up to and following the alert to identify any related suspicious activities or processes that may indicate a broader attack or compromise.
* Check for any recent changes or anomalies in system configurations or user permissions that could have facilitated the bypass attempt.
* Correlate the alert with other security logs or alerts to assess if this is part of a larger pattern of malicious behavior or an isolated incident.

**False positive analysis**

* System maintenance tools or backup software may legitimately use the mount_apfs command with the noowners flag for routine operations. Users can create exceptions for these specific tools by identifying their process names or paths and excluding them from the detection rule.
* Developers or IT administrators might use the mount_apfs command during testing or troubleshooting. To prevent these activities from triggering false positives, users can whitelist specific user accounts or IP addresses associated with these roles.
* Automated scripts or scheduled tasks that require access to APFS snapshots for legitimate purposes might trigger the rule. Users should review these scripts and, if deemed safe, add them to an exclusion list based on their unique identifiers or execution context.
* Security software or monitoring tools that perform regular checks on file system integrity might inadvertently match the rule’s criteria. Users can mitigate this by identifying these tools and excluding their specific process signatures from the detection parameters.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes related to the `mount_apfs` command to halt ongoing unauthorized access attempts.
* Conduct a thorough review of system logs and user activity to identify any data accessed or exfiltrated during the breach.
* Restore any compromised files from a known good backup to ensure data integrity and security.
* Update macOS and all installed applications to the latest versions to patch any vulnerabilities that may have been exploited.
* Implement stricter access controls and monitoring for APFS snapshot usage to prevent similar bypass attempts in the future.
* Escalate the incident to the security operations center (SOC) or relevant IT security team for further investigation and to assess the need for additional security measures.


## Setup [_setup_1397]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5557]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and process.name:mount_apfs and
  process.args:(/System/Volumes/Data and noowners)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Direct Volume Access
    * ID: T1006
    * Reference URL: [https://attack.mitre.org/techniques/T1006/](https://attack.mitre.org/techniques/T1006/)



