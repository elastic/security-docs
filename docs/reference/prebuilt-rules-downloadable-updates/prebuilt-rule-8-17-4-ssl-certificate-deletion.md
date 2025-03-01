---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ssl-certificate-deletion.html
---

# SSL Certificate Deletion [prebuilt-rule-8-17-4-ssl-certificate-deletion]

This rule detects the deletion of SSL certificates on a Linux system. Adversaries may delete SSL certificates to subvert trust controls and negatively impact the system.

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
* Tactic: Impact
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4360]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSL Certificate Deletion**

SSL certificates are crucial for establishing secure communications in Linux environments. Adversaries may delete these certificates to undermine trust and disrupt system operations, often as part of defense evasion tactics. The detection rule identifies suspicious deletions by monitoring specific directories for certificate files, excluding benign processes, thus highlighting potential malicious activity.

**Possible investigation steps**

* Review the alert details to confirm the file path and extension of the deleted SSL certificate, ensuring it matches the pattern "/etc/ssl/certs/*" with extensions "pem" or "crt".
* Identify the process responsible for the deletion by examining the process name and compare it against the exclusion list (e.g., "dockerd", "pacman") to determine if the process is potentially malicious.
* Investigate the user account associated with the process that performed the deletion to assess if the account has a history of suspicious activity or unauthorized access.
* Check system logs and audit trails around the time of the deletion event to identify any related activities or anomalies that could indicate a broader attack or compromise.
* Assess the impact of the certificate deletion on system operations and security, including any disruptions to secure communications or trust relationships.
* If the deletion is deemed suspicious, consider restoring the deleted certificate from backups and implementing additional monitoring to detect further unauthorized deletions.

**False positive analysis**

* Routine system updates or package installations may trigger certificate deletions. Exclude processes like package managers or update services that are known to perform these actions.
* Automated certificate renewal services might delete old certificates as part of their renewal process. Identify and exclude these services to prevent false alerts.
* Custom scripts or maintenance tasks that manage SSL certificates could be flagged. Review and whitelist these scripts if they are verified as non-malicious.
* Backup or cleanup operations that involve certificate files might cause false positives. Ensure these operations are recognized and excluded from monitoring.
* Development or testing environments where certificates are frequently added and removed can generate alerts. Consider excluding these environments if they are isolated and secure.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or damage.
* Verify the deletion of SSL certificates by checking the specified directories and confirm the absence of expected certificate files.
* Restore deleted SSL certificates from a secure backup to re-establish secure communications and trust controls.
* Conduct a thorough review of system logs and process activity to identify the source of the deletion and any associated malicious activity.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar environments to detect any further unauthorized deletions or related suspicious activities.
* Review and update access controls and permissions to ensure only authorized processes and users can modify or delete SSL certificates.


## Setup [_setup_1208]

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


## Rule query [_rule_query_5352]

```js
file where host.os.type == "linux" and event.type == "deletion" and file.path : "/etc/ssl/certs/*" and
file.extension in ("pem", "crt") and not process.name in ("dockerd", "pacman")
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

    * Name: File Deletion
    * ID: T1070.004
    * Reference URL: [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



