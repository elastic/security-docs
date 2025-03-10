---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-privilege-escalation-via-pkexec.html
---

# Potential Privilege Escalation via PKEXEC [prebuilt-rule-8-17-4-potential-privilege-escalation-via-pkexec]

Identifies an attempt to exploit a local privilege escalation in polkit pkexec (CVE-2021-4034) via unsecure environment variable injection. Successful exploitation allows an unprivileged user to escalate to the root user.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://seclists.org/oss-sec/2022/q1/80](https://seclists.org/oss-sec/2022/q1/80)
* [https://haxx.in/files/blasty-vs-pkexec.c](https://haxx.in/files/blasty-vs-pkexec.c)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4528]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via PKEXEC**

Polkit’s pkexec is a command-line utility that allows an authorized user to execute commands as another user, typically root, in Linux environments. Adversaries exploit vulnerabilities like CVE-2021-4034 by injecting unsecure environment variables, enabling unauthorized privilege escalation. The detection rule identifies suspicious file paths indicative of such exploitation attempts, focusing on environment variable manipulation to preemptively flag potential threats.

**Possible investigation steps**

* Review the alert details to confirm the presence of the file path pattern "/**GCONV_PATH**" on a Linux host, as this is indicative of the potential exploitation attempt.
* Examine the process execution history on the affected host to identify any instances of pkexec being executed around the time of the alert. Look for unusual or unauthorized command executions.
* Check the environment variables set during the pkexec execution to identify any suspicious or unauthorized modifications that could indicate an exploitation attempt.
* Investigate the user account associated with the alert to determine if it has a history of privilege escalation attempts or other suspicious activities.
* Analyze system logs and security events for any additional indicators of compromise or related suspicious activities that occurred before or after the alert.
* Assess the patch status of the affected system to determine if it is vulnerable to CVE-2021-4034 and ensure that appropriate security updates have been applied.

**False positive analysis**

* Routine administrative tasks involving pkexec may trigger alerts if they involve environment variable manipulation. Review the context of the command execution to determine if it aligns with expected administrative behavior.
* Custom scripts or applications that legitimately use environment variables in their execution paths might be flagged. Identify these scripts and consider adding them to an exception list if they are verified as non-threatening.
* Automated system management tools that modify environment variables for legitimate purposes could cause false positives. Monitor these tools and exclude their known safe operations from the detection rule.
* Development environments where developers frequently test applications with varying environment variables might generate alerts. Establish a baseline of normal activity and exclude these patterns if they are consistent and verified as safe.
* Scheduled tasks or cron jobs that involve environment variable changes should be reviewed. If they are part of regular system maintenance, document and exclude them from triggering alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the attacker.
* Terminate any suspicious processes associated with pkexec or unauthorized privilege escalation attempts to halt ongoing exploitation.
* Conduct a thorough review of system logs and file access records to identify any unauthorized changes or access patterns, focusing on the presence of GCONV_PATH in file paths.
* Revert any unauthorized changes made by the attacker, such as modifications to critical system files or configurations, to restore system integrity.
* Apply the latest security patches and updates to the polkit package to address CVE-2021-4034 and prevent future exploitation.
* Implement enhanced monitoring and alerting for similar privilege escalation attempts, ensuring that any future attempts are detected and responded to promptly.
* Report the incident to relevant internal security teams and, if necessary, escalate to external authorities or cybersecurity partners for further investigation and support.


## Setup [_setup_1360]

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


## Rule query [_rule_query_5520]

```js
file where host.os.type == "linux" and file.path : "/*GCONV_PATH*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Path Interception by PATH Environment Variable
    * ID: T1574.007
    * Reference URL: [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)



