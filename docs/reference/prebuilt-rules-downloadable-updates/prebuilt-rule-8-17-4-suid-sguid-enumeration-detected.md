---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suid-sguid-enumeration-detected.html
---

# SUID/SGUID Enumeration Detected [prebuilt-rule-8-17-4-suid-sguid-enumeration-detected]

This rule monitors for the usage of the "find" command in conjunction with SUID and SGUID permission arguments. SUID (Set User ID) and SGID (Set Group ID) are special permissions in Linux that allow a program to execute with the privileges of the file owner or group, respectively, rather than the privileges of the user running the program. In case an attacker is able to enumerate and find a binary that is misconfigured, they might be able to leverage this misconfiguration to escalate privileges by exploiting vulnerabilities or built-in features in the privileged program.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4380]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SUID/SGUID Enumeration Detected**

In Linux, SUID and SGID permissions allow programs to execute with elevated privileges, potentially exposing systems to privilege escalation if misconfigured. Adversaries exploit this by searching for binaries with these permissions to gain unauthorized access. The detection rule identifies suspicious use of the "find" command to locate such binaries, flagging potential misuse by monitoring specific command arguments and execution contexts.

**Possible investigation steps**

* Review the process execution details to confirm the use of the "find" command with SUID/SGID permission arguments by checking the process.name and process.args fields.
* Identify the user and group context in which the command was executed by examining the user.Ext.real.id and group.Ext.real.id fields to determine if the command was run by a non-root user.
* Analyze the command’s arguments to understand the scope of the search, focusing on the process.args field to see if specific directories or files were targeted.
* Check for any other suspicious activities or commands executed by the same user or process around the same time to identify potential follow-up actions or privilege escalation attempts.
* Investigate the system for any newly created or modified files with SUID/SGID permissions that could indicate successful privilege escalation or preparation for future attacks.

**False positive analysis**

* System administrators or security tools may use the find command with SUID/SGID arguments for legitimate audits. To handle this, create exceptions for known administrative users or specific scripts that regularly perform these checks.
* Automated scripts or cron jobs might execute the find command with these arguments as part of routine maintenance tasks. Identify these scripts and exclude them from monitoring by specifying their process paths or user IDs.
* Some legitimate software installations or updates might temporarily use the find command with SUID/SGID arguments. Monitor installation logs and exclude these processes by correlating them with known software update activities.
* Developers or testers might use the find command in development environments to test security configurations. Exclude these environments from the rule by specifying their hostnames or IP addresses in the exception list.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, particularly those involving the "find" command with SUID/SGID arguments.
* Conduct a thorough review of the system’s SUID/SGID binaries to identify any misconfigurations or unauthorized changes. Remove or correct permissions on any binaries that are not required to have elevated privileges.
* Implement additional monitoring on the affected system to detect any further attempts to exploit SUID/SGID binaries, focusing on process execution and permission changes.
* Escalate the incident to the security operations team for a deeper forensic analysis to determine the scope of the compromise and identify any other affected systems.
* Apply patches and updates to the system and any vulnerable applications to mitigate known vulnerabilities that could be exploited through SUID/SGID binaries.
* Review and enhance access controls and privilege management policies to minimize the risk of privilege escalation through misconfigured binaries in the future.


## Setup [_setup_1227]

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


## Rule query [_rule_query_5372]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "find" and process.args : "-perm" and process.args : (
  "/6000", "-6000", "/4000", "-4000", "/2000", "-2000", "/u=s", "-u=s", "/g=s", "-g=s", "/u=s,g=s", "/g=s,u=s"
) and not (
  user.Ext.real.id == "0" or group.Ext.real.id == "0" or process.args_count >= 12 or
  (process.args : "/usr/bin/pkexec" and process.args : "-xdev" and process.args_count == 7)
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: File and Directory Discovery
    * ID: T1083
    * Reference URL: [https://attack.mitre.org/techniques/T1083/](https://attack.mitre.org/techniques/T1083/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Setuid and Setgid
    * ID: T1548.001
    * Reference URL: [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



