---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/sensitive-files-compression.html
---

# Sensitive Files Compression [sensitive-files-compression]

Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials and system configurations.

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

* [https://www.trendmicro.com/en_ca/research/20/l/teamtnt-now-deploying-ddos-capable-irc-bot-tntbotinger.html](https://www.trendmicro.com/en_ca/research/20/l/teamtnt-now-deploying-ddos-capable-irc-bot-tntbotinger.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Collection
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_915]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sensitive Files Compression**

Compression utilities like zip, tar, and gzip are essential for efficiently managing and transferring files. However, adversaries can exploit these tools to compress and exfiltrate sensitive data, such as SSH keys and configuration files. The detection rule identifies suspicious compression activities by monitoring process executions involving these utilities and targeting known sensitive file paths, thereby flagging potential data collection and credential access attempts.

**Possible investigation steps**

* Review the process execution details to identify the user account associated with the compression activity, focusing on the process.name and process.args fields.
* Examine the command line arguments (process.args) to determine which specific sensitive files were targeted for compression.
* Check the event.timestamp to establish a timeline and correlate with other potentially suspicious activities on the host.
* Investigate the host’s recent login history and user activity to identify any unauthorized access attempts or anomalies.
* Analyze network logs for any outbound connections from the host around the time of the event to detect potential data exfiltration attempts.
* Assess the integrity and permissions of the sensitive files involved to determine if they have been altered or accessed inappropriately.

**False positive analysis**

* Routine system backups or administrative tasks may trigger the rule if they involve compressing sensitive files for legitimate purposes. Users can create exceptions for known backup scripts or administrative processes by excluding specific process names or command-line arguments associated with these tasks.
* Developers or system administrators might compress configuration files during development or deployment processes. To handle this, users can whitelist specific user accounts or directories commonly used for development activities, ensuring these actions are not flagged as suspicious.
* Automated scripts or cron jobs that regularly archive logs or configuration files could be mistakenly identified as threats. Users should review and exclude these scheduled tasks by identifying their unique process identifiers or execution patterns.
* Security tools or monitoring solutions that periodically compress and transfer logs for analysis might be misinterpreted as malicious. Users can exclude these tools by specifying their process names or paths in the detection rule exceptions.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further data exfiltration and unauthorized access.
* Terminate any suspicious processes identified by the detection rule to halt ongoing compression and potential data exfiltration activities.
* Conduct a thorough review of the compressed files and their contents to assess the extent of sensitive data exposure and determine if any data has been exfiltrated.
* Change all credentials associated with the compromised files, such as SSH keys and AWS credentials, to prevent unauthorized access using stolen credentials.
* Restore any altered or deleted configuration files from a known good backup to ensure system integrity and functionality.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for compression utilities and sensitive file access to detect and respond to similar threats more effectively in the future.


## Setup [_setup_578]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
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


## Rule query [_rule_query_972]

```js
event.category:process and host.os.type:linux and event.type:start and
  process.name:(zip or tar or gzip or hdiutil or 7z) and
  process.args:
    (
      /root/.ssh/id_rsa or
      /root/.ssh/id_rsa.pub or
      /root/.ssh/id_ed25519 or
      /root/.ssh/id_ed25519.pub or
      /root/.ssh/authorized_keys or
      /root/.ssh/authorized_keys2 or
      /root/.ssh/known_hosts or
      /root/.bash_history or
      /etc/hosts or
      /home/*/.ssh/id_rsa or
      /home/*/.ssh/id_rsa.pub or
      /home/*/.ssh/id_ed25519 or
      /home/*/.ssh/id_ed25519.pub or
      /home/*/.ssh/authorized_keys or
      /home/*/.ssh/authorized_keys2 or
      /home/*/.ssh/known_hosts or
      /home/*/.bash_history or
      /root/.aws/credentials or
      /root/.aws/config or
      /home/*/.aws/credentials or
      /home/*/.aws/config or
      /root/.docker/config.json or
      /home/*/.docker/config.json or
      /etc/group or
      /etc/passwd or
      /etc/shadow or
      /etc/gshadow
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Credentials In Files
    * ID: T1552.001
    * Reference URL: [https://attack.mitre.org/techniques/T1552/001/](https://attack.mitre.org/techniques/T1552/001/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

* Sub-technique:

    * Name: Archive via Utility
    * ID: T1560.001
    * Reference URL: [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)



