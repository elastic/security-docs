---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privacy-control-bypass-via-localhost-secure-copy.html
---

# Potential Privacy Control Bypass via Localhost Secure Copy [potential-privacy-control-bypass-via-localhost-secure-copy]

Identifies use of the Secure Copy Protocol (SCP) to copy files locally by abusing the auto addition of the Secure Shell Daemon (sshd) to the authorized application list for Full Disk Access. This may indicate attempts to bypass macOS privacy controls to access sensitive files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware—​infects-xcode-projects—​uses-0-days.html](https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware—​infects-xcode-projects—​uses-0-days.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_730]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privacy Control Bypass via Localhost Secure Copy**

Secure Copy Protocol (SCP) is used for secure file transfers over SSH. On macOS, SSH daemon inclusion in the Full Disk Access list can be exploited to bypass privacy controls. Adversaries may misuse SCP to locally copy files, evading security measures. The detection rule identifies such activity by monitoring SCP commands targeting localhost, excluding benign uses like Vagrant, to flag potential privacy control bypass attempts.

**Possible investigation steps**

* Review the process details to confirm the presence of SCP commands targeting localhost or 127.0.0.1, as indicated by the process.command_line field.
* Check the process.args field for the presence of "StrictHostKeyChecking=no" to verify if the SCP command was executed with potentially insecure settings.
* Investigate the user account associated with the SCP command to determine if it is a legitimate user or potentially compromised.
* Examine the timing and frequency of the SCP command execution to identify any unusual patterns or repeated attempts that may indicate malicious activity.
* Cross-reference the alert with other security logs or alerts to identify any related suspicious activities or anomalies around the same timeframe.
* Assess the system for any unauthorized changes or access to sensitive files that may have occurred as a result of the SCP command execution.

**False positive analysis**

* Vagrant usage can trigger false positives due to its legitimate use of SCP for local file transfers. To mitigate this, ensure that Vagrant-related SCP commands are excluded by refining the detection rule to ignore processes with arguments containing "vagrant@**127.0.0.1**".
* Development and testing environments may frequently use SCP to localhost for legitimate purposes. Consider creating exceptions for known development tools or scripts that regularly perform these actions to reduce noise.
* Automated backup solutions might use SCP to copy files locally as part of their routine operations. Identify and whitelist these processes to prevent them from being flagged as potential threats.
* System administrators may use SCP for local file management tasks. Establish a list of trusted administrator accounts or specific command patterns that can be safely excluded from triggering alerts.
* Continuous integration and deployment pipelines might involve SCP commands to localhost. Review and exclude these processes if they are part of a controlled and secure workflow.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious SCP processes identified in the alert to halt ongoing unauthorized file transfers.
* Conduct a thorough review of the system’s Full Disk Access list to identify and remove any unauthorized applications, including the SSH daemon if it was added without proper authorization.
* Analyze the system’s SSH configuration and logs to identify any unauthorized changes or access patterns, and revert any suspicious modifications.
* Reset credentials for any accounts that may have been compromised, focusing on those with SSH access, and enforce the use of strong, unique passwords.
* Implement network monitoring to detect and alert on any future SCP commands targeting localhost, especially those bypassing host key checks.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on sensitive data, ensuring compliance with organizational incident response protocols.


## Setup [_setup_465]

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


## Rule query [_rule_query_777]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name:"scp" and
 process.args:"StrictHostKeyChecking=no" and
 process.command_line:("scp *localhost:/*", "scp *127.0.0.1:/*") and
 not process.args:"vagrant@*127.0.0.1*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)



