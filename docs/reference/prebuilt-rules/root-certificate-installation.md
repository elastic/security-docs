---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/root-certificate-installation.html
---

# Root Certificate Installation [root-certificate-installation]

This rule detects the installation of root certificates on a Linux system. Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to their command and control servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root’s chain of trust that have been signed by the root certificate.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md](https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_883]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Root Certificate Installation**

Root certificates are pivotal in establishing trust within public key infrastructures, enabling secure communications by verifying the authenticity of entities. Adversaries exploit this by installing rogue root certificates on compromised Linux systems, thus bypassing security warnings and facilitating undetected command and control communications. The detection rule identifies suspicious certificate installations by monitoring specific processes and excluding legitimate parent processes, thereby highlighting potential unauthorized activities.

**Possible investigation steps**

* Review the process details to confirm the execution of "update-ca-trust" or "update-ca-certificates" on the Linux host, focusing on the event type "start" and action "exec" or "exec_event".
* Examine the parent process name and arguments to ensure they do not match any of the legitimate exclusions such as "ca-certificates.postinst", "pacman", or "/var/tmp/rpm*".
* Investigate the user account associated with the process to determine if it is a known or expected user for such operations.
* Check the system logs and recent changes to identify any unauthorized modifications or installations that coincide with the alert.
* Correlate the alert with other security events or logs to identify any potential command and control communications or other suspicious activities on the host.
* Assess the network connections from the host around the time of the alert to detect any unusual or unauthorized outbound traffic.

**False positive analysis**

* Legitimate system updates or package installations may trigger the rule when processes like "update-ca-trust" or "update-ca-certificates" are executed by trusted package managers such as "pacman" or "pamac-daemon". To mitigate this, ensure these parent processes are included in the exclusion list.
* Automated scripts or system maintenance tasks that use shell scripts (e.g., "sh", "bash", "zsh") to update certificates might be flagged. If these scripts are verified as safe, consider adding specific script names or paths to the exclusion criteria.
* Custom applications or services that require certificate updates and are known to be safe can be excluded by adding their parent process names to the exclusion list, ensuring they do not trigger false alerts.
* Security tools or agents like "kesl" or "execd" that manage certificates as part of their operations may cause false positives. Verify their activities and include them in the exclusion list if they are part of legitimate security operations.
* Temporary files or scripts located in directories like "/var/tmp/rpm*" used during legitimate installations should be reviewed and excluded if they are part of routine system operations.

**Response and remediation**

* Immediately isolate the affected Linux system from the network to prevent further unauthorized communications with potential command and control servers.
* Revoke any unauthorized root certificates installed on the system by removing them from the trusted certificate store to restore the integrity of the system’s trust chain.
* Conduct a thorough review of system logs and process execution history to identify any additional unauthorized activities or changes made by the adversary.
* Restore the system from a known good backup if unauthorized changes or persistent threats are detected that cannot be easily remediated.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited by the adversary.
* Implement enhanced monitoring and alerting for similar suspicious activities, focusing on process executions related to certificate management.
* Escalate the incident to the security operations center (SOC) or relevant incident response team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_565]

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


## Rule query [_rule_query_939]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name in ("update-ca-trust", "update-ca-certificates") and not (
  process.parent.name like (
    "ca-certificates.postinst", "ca-certificates-*.trigger", "pacman", "pamac-daemon", "autofirma.postinst",
    "ipa-client-install", "su", "platform-python", "python*", "kesl", "execd", "systemd", "flock"
  ) or
  process.parent.args like "/var/tmp/rpm*" or
  (process.parent.name in ("sh", "bash", "zsh") and process.args == "-e")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Sub-technique:

    * Name: Install Root Certificate
    * ID: T1553.004
    * Reference URL: [https://attack.mitre.org/techniques/T1553/004/](https://attack.mitre.org/techniques/T1553/004/)



