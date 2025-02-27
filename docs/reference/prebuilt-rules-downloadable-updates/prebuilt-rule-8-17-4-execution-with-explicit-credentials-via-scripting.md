---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-execution-with-explicit-credentials-via-scripting.html
---

# Execution with Explicit Credentials via Scripting [prebuilt-rule-8-17-4-execution-with-explicit-credentials-via-scripting]

Identifies execution of the security_authtrampoline process via a scripting interpreter. This occurs when programs use AuthorizationExecute-WithPrivileges from the Security.framework to run another program with root privileges. It should not be run by itself, as this is a sign of execution with explicit logon credentials.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)
* [https://www.manpagez.com/man/8/security_authtrampoline/](https://www.manpagez.com/man/8/security_authtrampoline/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4603]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution with Explicit Credentials via Scripting**

In macOS environments, the `security_authtrampoline` process is used to execute programs with elevated privileges via scripting interpreters. Adversaries may exploit this by using explicit credentials to run unauthorized scripts, gaining root access. The detection rule identifies such activities by monitoring the initiation of `security_authtrampoline` through common scripting languages, flagging potential privilege escalation attempts.

**Possible investigation steps**

* Review the process details to confirm the parent process name matches one of the specified scripting interpreters (e.g., osascript, bash, python) to verify the context of the alert.
* Examine the command line arguments of the security_authtrampoline process to identify the script or program being executed and assess its legitimacy.
* Investigate the user account associated with the process to determine if the credentials used are valid and expected for executing such scripts.
* Check the historical activity of the involved user account and associated processes to identify any patterns of unusual or unauthorized behavior.
* Correlate the alert with other security events or logs from the same host to identify any additional indicators of compromise or related suspicious activities.
* Assess the system for any signs of compromise or unauthorized changes, such as unexpected new files, altered configurations, or additional unauthorized processes running.

**False positive analysis**

* Legitimate administrative tasks using scripting languages may trigger this rule. Users should review the context of the script execution to determine if it aligns with expected administrative activities.
* Automated scripts or scheduled tasks that require elevated privileges might be flagged. Consider creating exceptions for known scripts by specifying their hash or path in the monitoring system.
* Development or testing environments where developers frequently use scripting languages to test applications with elevated privileges can cause false positives. Implement a policy to exclude these environments from the rule or adjust the risk score to reflect the lower threat level.
* Security tools or software updates that use scripting interpreters to perform legitimate actions with elevated privileges may be mistakenly identified. Verify the source and purpose of such processes and whitelist them if they are deemed safe.
* User-initiated scripts for personal productivity that require elevated access could be misinterpreted as threats. Educate users on safe scripting practices and establish a process for them to report and document legitimate use cases for exclusion.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement.
* Terminate the `security_authtrampoline` process if it is still running to stop any ongoing unauthorized activities.
* Review and revoke any compromised credentials used in the execution of the unauthorized script to prevent further misuse.
* Conduct a thorough examination of the system for any additional unauthorized scripts or malware that may have been deployed using the compromised credentials.
* Restore the system from a known good backup if any unauthorized changes or persistent threats are detected.
* Implement stricter access controls and monitoring for the use of scripting interpreters and the `security_authtrampoline` process to prevent similar privilege escalation attempts.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1435]

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


## Rule query [_rule_query_5595]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:"security_authtrampoline" and
 process.parent.name:(osascript or com.apple.automator.runner or sh or bash or dash or zsh or python* or Python or perl* or php* or ruby or pwsh)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Elevated Execution with Prompt
    * ID: T1548.004
    * Reference URL: [https://attack.mitre.org/techniques/T1548/004/](https://attack.mitre.org/techniques/T1548/004/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



