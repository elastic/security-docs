---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-hidden-shared-object-file.html
---

# Creation of Hidden Shared Object File [creation-of-hidden-shared-object-file]

Identifies the creation of a hidden shared object (.so) file. Users can mark specific files as hidden simply by putting a "." as the first character in the file or folder name. Adversaries can use this to their advantage to hide files and folders on the system for persistence and defense evasion.

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

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_240]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Creation of Hidden Shared Object File**

Shared object files (.so) are dynamic libraries used in Linux environments to provide reusable code. Adversaries may exploit the ability to hide files by prefixing them with a dot, concealing malicious .so files for persistence and evasion. The detection rule identifies the creation of such hidden files, excluding benign processes like Docker, to flag potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific hidden shared object file (.so) that was created, noting its full path and filename.
* Investigate the process that created the file by examining the process name and its parent process, excluding "dockerd" as per the query, to determine if the process is legitimate or potentially malicious.
* Check the file creation timestamp and correlate it with other system activities or logs to identify any suspicious behavior or patterns around the time of creation.
* Analyze the contents of the hidden .so file, if accessible, to determine its purpose and whether it contains any malicious code or indicators of compromise.
* Investigate the user account associated with the file creation event to assess if the account has been compromised or is involved in unauthorized activities.
* Search for any other hidden files or suspicious activities on the system that may indicate a broader compromise or persistence mechanism.

**False positive analysis**

* Development and testing environments may frequently create hidden .so files as part of routine operations. Users can mitigate this by excluding specific directories or processes known to be part of development workflows.
* Backup or system maintenance scripts might generate hidden .so files temporarily. Identify and exclude these scripts or their associated processes to prevent false alerts.
* Some legitimate software installations or updates may create hidden .so files as part of their setup process. Users should monitor installation logs and whitelist these processes if they are verified as non-threatening.
* Custom applications or services that use hidden .so files for legitimate purposes should be documented, and their creation processes should be excluded from detection to avoid unnecessary alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes associated with the creation of the hidden .so file, except for known benign processes like Docker.
* Remove the hidden .so file from the system to eliminate the immediate threat. Ensure that the file is securely deleted to prevent recovery.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or artifacts.
* Review system logs and process execution history to identify any unauthorized access or changes made around the time of the file creation. This can help in understanding the scope of the compromise.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar activities, such as the creation of hidden files, to improve detection and response times for future incidents.


## Setup [_setup_159]

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
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).

**Custom Ingest Pipeline**

For versions <8.2, you need to add a custom ingest pipeline to populate `event.ingested` with @timestamp for non-elastic-agent indexes, like auditbeats/filebeat/winlogbeat etc. For more details to add a custom ingest pipeline refer to the [guide](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md).


## Rule query [_rule_query_249]

```js
file where host.os.type == "linux" and event.type == "creation" and file.extension == "so" and file.name : ".*.so" and
not process.name in ("dockerd", "azcopy", "podman")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)



