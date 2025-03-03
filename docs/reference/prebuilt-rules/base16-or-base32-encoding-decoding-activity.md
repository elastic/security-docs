---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/base16-or-base32-encoding-decoding-activity.html
---

# Base16 or Base32 Encoding/Decoding Activity [base16-or-base32-encoding-decoding-activity]

Adversaries may encode/decode data in an attempt to evade detection by host- or network-based security controls.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_209]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Base16 or Base32 Encoding/Decoding Activity**

Base16 and Base32 are encoding schemes used to convert binary data into text, facilitating data transmission and storage. Adversaries exploit these encodings to obfuscate malicious payloads, evading detection by security systems. The detection rule identifies suspicious encoding/decoding activities on Linux systems by monitoring specific processes and actions, excluding benign uses like help or version checks.

**Possible investigation steps**

* Review the process name and arguments to confirm if the activity is related to encoding/decoding using base16 or base32, ensuring it is not a benign use case like help or version checks.
* Examine the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Check the parent process of the encoding/decoding activity to identify if it was initiated by a legitimate application or a potentially malicious script or program.
* Investigate the timing and frequency of the encoding/decoding events to assess if they coincide with other suspicious activities or known attack patterns.
* Correlate the event with network activity logs to see if there is any data exfiltration attempt or communication with known malicious IP addresses or domains.
* Look into any recent changes or anomalies in the system that might indicate a compromise, such as unauthorized file modifications or new user accounts.

**False positive analysis**

* Routine administrative tasks may trigger the rule if administrators use base16 or base32 commands for legitimate data encoding or decoding. To manage this, create exceptions for specific user accounts or scripts known to perform these tasks regularly.
* Automated backup or data transfer processes might use base16 or base32 encoding as part of their operations. Identify these processes and exclude them by specifying their unique process arguments or execution paths.
* Development and testing environments often involve encoding and decoding operations for debugging or data manipulation. Exclude these environments by filtering based on hostnames or IP addresses associated with non-production systems.
* Security tools or scripts that perform regular encoding checks for data integrity or compliance purposes can also trigger false positives. Whitelist these tools by their process names or execution contexts to prevent unnecessary alerts.
* Educational or research activities involving encoding techniques may inadvertently match the rule criteria. Consider excluding known educational user groups or specific research project identifiers to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those involving base16 or base32 encoding/decoding without benign arguments.
* Conduct a thorough review of recent system logs and process execution history to identify any additional suspicious activities or related processes.
* Remove any malicious files or payloads that have been identified as part of the encoding/decoding activity.
* Restore any affected files or systems from known good backups to ensure system integrity and data accuracy.
* Update and patch the affected system to close any vulnerabilities that may have been exploited by the adversary.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_144]

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


## Rule query [_rule_query_214]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name in ("base16", "base32", "base32plain", "base32hex") and
not process.args in ("--help", "--version")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)



