---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-overlayfs.html
---

# Potential Privilege Escalation via OverlayFS [potential-privilege-escalation-via-overlayfs]

Identifies an attempt to exploit a local privilege escalation (CVE-2023-2640 and CVE-2023-32629) via a flaw in Ubuntu’s modifications to OverlayFS. These flaws allow the creation of specialized executables, which, upon execution, grant the ability to escalate privileges to root on the affected machine.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability)
* [https://twitter.com/liadeliyahu/status/1684841527959273472](https://twitter.com/liadeliyahu/status/1684841527959273472)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_738]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via OverlayFS**

OverlayFS is a union filesystem used in Linux environments to overlay one filesystem on top of another, allowing for efficient file management and updates. Adversaries exploit vulnerabilities in Ubuntu’s OverlayFS modifications to execute crafted executables that escalate privileges to root. The detection rule identifies suspicious sequences involving the *unshare* command with specific arguments and subsequent UID changes to root, indicating potential exploitation attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of the *unshare* command with the specific arguments *-r*, *-rm*, *m*, and ***cap_setuid*** as indicated in the query. This will help verify if the command execution aligns with the known exploitation pattern.
* Check the process tree and parent process information using the process.parent.entity_id to understand the context in which the *unshare* command was executed. This can provide insights into whether the command was part of a legitimate operation or a potential attack.
* Investigate the user account associated with the process execution (user.id != "0") to determine if the account has a history of suspicious activity or if it has been compromised.
* Examine the host.id and host.os.type fields to identify the specific Linux host involved and assess its vulnerability status regarding CVE-2023-2640 and CVE-2023-32629. This can help determine if the host is susceptible to the exploitation attempt.
* Analyze any subsequent UID changes to root (user.id == "0") to confirm if the privilege escalation was successful and identify any unauthorized access or actions taken by the elevated process.
* Review system logs and other security alerts around the time of the event to identify any additional indicators of compromise or related suspicious activities that might corroborate the exploitation attempt.

**False positive analysis**

* Legitimate administrative tasks using the *unshare* command with similar arguments may trigger the rule. Review the context of the command execution and verify if it aligns with routine system maintenance or configuration changes.
* Automated scripts or system management tools that utilize *unshare* for containerization or namespace isolation might cause false positives. Identify these scripts and consider excluding their specific process names or paths from the rule.
* Development environments where developers frequently test applications with elevated privileges could inadvertently match the rule criteria. Implement user-based exceptions for known developer accounts to reduce noise.
* Security tools or monitoring solutions that simulate privilege escalation scenarios for testing purposes may be flagged. Whitelist these tools by their process hash or signature to prevent unnecessary alerts.
* Custom applications that require temporary privilege elevation for legitimate operations should be reviewed. If deemed safe, add these applications to an exception list based on their unique identifiers.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, particularly those involving the *unshare* command with the specified arguments.
* Conduct a thorough review of user accounts and privileges on the affected system to ensure no unauthorized changes have been made, especially focusing on accounts with root access.
* Apply the latest security patches and updates to the affected system, specifically addressing CVE-2023-2640 and CVE-2023-32629, to mitigate the vulnerability in OverlayFS.
* Monitor for any further attempts to exploit the vulnerability by setting up alerts for similar sequences of commands and UID changes.
* Escalate the incident to the security operations team for a detailed forensic analysis to understand the scope and impact of the exploitation attempt.
* Implement additional security measures, such as enhanced logging and monitoring, to detect and respond to privilege escalation attempts more effectively in the future.


## Setup [_setup_473]

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


## Rule query [_rule_query_785]

```js
sequence by process.parent.entity_id, host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
    process.name == "unshare" and process.args : ("-r", "-rm", "m") and process.args : "*cap_setuid*"  and user.id != "0"]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
    user.id == "0"]
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



