---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-system-log-file-deletion.html
---

# System Log File Deletion [prebuilt-rule-8-17-4-system-log-file-deletion]

Identifies the deletion of sensitive Linux system logs. This may indicate an attempt to evade detection or destroy forensic evidence on a system.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2020/11/live-off-the-land-an-overview-of-unc1945.html](https://www.fireeye.com/blog/threat-research/2020/11/live-off-the-land-an-overview-of-unc1945.md)
* [https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security](https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4352]

**Triage and analysis**

[TBC: QUOTE]
**Investigating System Log File Deletion**

System logs are crucial for monitoring and auditing activities on Linux systems, providing insights into system events and user actions. Adversaries may delete these logs to cover their tracks, hindering forensic investigations. The detection rule identifies suspicious deletions of key log files, excluding benign processes like compression tools, to flag potential evasion attempts. This helps security analysts quickly respond to and investigate unauthorized log deletions.

**Possible investigation steps**

* Review the specific file path involved in the deletion event to determine which log file was targeted, using the file.path field from the alert.
* Investigate the process responsible for the deletion by examining the process.name and related process metadata to identify any suspicious or unauthorized activity.
* Check for any recent login or session activity around the time of the log deletion by reviewing other logs or authentication records, focusing on the /var/log/auth.log and /var/log/secure files if they are still available.
* Analyze the user account associated with the deletion event to determine if it has a history of suspicious activity or if it was potentially compromised.
* Correlate the deletion event with other security alerts or anomalies in the system to identify any patterns or related incidents that might indicate a broader attack or compromise.
* Assess the impact of the log deletion on the system’s security posture and determine if any critical forensic evidence has been lost, considering the importance of the deleted log file.

**False positive analysis**

* Compression tools like gzip may trigger false positives when they temporarily delete log files during compression. To mitigate this, ensure gzip is included in the exclusion list within the detection rule.
* Automated system maintenance scripts might delete or rotate log files as part of routine operations. Review these scripts and add their process names to the exclusion list if they are verified as non-threatening.
* Docker-related processes, such as dockerd, can also cause false positives when managing container logs. Confirm these activities are legitimate and include dockerd in the exclusion list to prevent unnecessary alerts.
* Custom backup or log management tools may delete logs as part of their normal function. Identify these tools and add their process names to the exclusion list after verifying their benign nature.
* Scheduled tasks or cron jobs that manage log files should be reviewed. If they are confirmed to be safe, their associated process names should be added to the exclusion list to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data tampering.
* Conduct a thorough review of user accounts and permissions on the affected system to identify any unauthorized access or privilege escalation.
* Restore deleted log files from backups if available, to aid in further forensic analysis and to maintain system integrity.
* Implement enhanced monitoring on the affected system and similar systems to detect any further unauthorized log deletions or suspicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the scope of the breach.
* Review and update security policies and configurations to ensure that only authorized processes can delete critical log files, leveraging access controls and audit policies.
* Consider deploying additional endpoint detection and response (EDR) solutions to improve visibility and detection capabilities for similar threats in the future.


## Setup [_setup_1200]

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

**Custom Ingest Pipeline**

For versions <8.2, you need to add a custom ingest pipeline to populate `event.ingested` with @timestamp for non-elastic-agent indexes, like auditbeats/filebeat/winlogbeat etc. For more details to add a custom ingest pipeline refer to the [guide](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md).


## Rule query [_rule_query_5344]

```js
file where host.os.type == "linux" and event.type == "deletion" and
  file.path :
    (
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/faillog",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/auth.log",
    "/var/log/boot.log",
    "/var/log/kern.log",
    "/var/log/dmesg"
    ) and
    not process.name in ("gzip", "executor", "dockerd")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Linux or Mac System Logs
    * ID: T1070.002
    * Reference URL: [https://attack.mitre.org/techniques/T1070/002/](https://attack.mitre.org/techniques/T1070/002/)



