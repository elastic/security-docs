---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-git-hook-egress-network-connection.html
---

# Git Hook Egress Network Connection [prebuilt-rule-8-17-4-git-hook-egress-network-connection]

This rule detects a suspicious egress network connection attempt from a Git hook script. Git hooks are scripts that Git executes before or after events such as: commit, push, and receive. An attacker can abuse these features to execute arbitrary commands on the system, establish persistence or to initialize a network connection to a remote server and exfiltrate data or download additional payloads.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* logs-endpoint.events.network*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4454]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Git Hook Egress Network Connection**

Git hooks are scripts that automate tasks during Git operations like commits or pushes. Adversaries can exploit these hooks to execute unauthorized commands, maintain persistence, or initiate network connections for data exfiltration. The detection rule identifies suspicious network activities by monitoring script executions from Git hooks and subsequent egress connections to non-local IPs, flagging potential misuse.

**Possible investigation steps**

* Review the process execution details to identify the specific Git hook script that triggered the alert. Check the process.args field for the exact script path within the .git/hooks directory.
* Investigate the parent process details to confirm the legitimacy of the Git operation. Verify the process.parent.name is "git" and assess whether the Git activity aligns with expected user or system behavior.
* Analyze the destination IP address involved in the network connection attempt. Use the destination.ip field to determine if the IP is known, trusted, or associated with any malicious activity.
* Check for any additional network connections from the same host around the time of the alert to identify potential patterns or additional suspicious activity.
* Correlate the alert with any recent changes in the repository or system that might explain the execution of the Git hook, such as recent commits or updates.
* Review user activity logs to determine if the Git operation was performed by an authorized user and if their actions align with their typical behavior.
* If suspicious activity is confirmed, isolate the affected system to prevent further unauthorized access or data exfiltration and initiate a deeper forensic analysis.

**False positive analysis**

* Legitimate automated scripts or CI/CD pipelines may trigger Git hooks to perform network operations. Review the source and purpose of these scripts and consider excluding them if they are verified as non-threatening.
* Development environments often use Git hooks for tasks like fetching dependencies or updating remote services. Identify these common operations and create exceptions for known safe IP addresses or domains.
* Internal tools or services that rely on Git hooks for communication with other internal systems might be flagged. Ensure these tools are documented and whitelist their network activities if they are deemed secure.
* Frequent updates or deployments that involve Git hooks could lead to repeated alerts. Monitor the frequency and context of these alerts to determine if they are part of regular operations and adjust the rule to reduce noise.
* Consider the context of the network connection, such as the destination IP or domain. If the destination is a known and trusted entity, it may be appropriate to exclude it from triggering alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized egress connections and potential data exfiltration.
* Terminate any suspicious processes identified as originating from Git hooks, particularly those executing shell scripts like bash, dash, or zsh.
* Conduct a thorough review of the .git/hooks directory on the affected system to identify and remove any unauthorized or malicious scripts.
* Reset credentials and access tokens associated with the affected Git repository to prevent further unauthorized access.
* Restore any modified or deleted files from a known good backup to ensure system integrity.
* Implement network monitoring to detect and block any future unauthorized egress connections from Git hooks or similar scripts.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems or repositories.


## Setup [_setup_1297]

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


## Rule query [_rule_query_5446]

```js
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "git" and process.args : ".git/hooks/*" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.entity_id
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8", "172.31.0.0/16"
     )
   )
  ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



