---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-user-privilege-enumeration-via-id.html
---

# Unusual User Privilege Enumeration via id [unusual-user-privilege-enumeration-via-id]

This rule monitors for a sequence of 20 "id" command executions within 1 second by the same parent process. This behavior is unusual, and may be indicative of the execution of an enumeration script such as LinPEAS or LinEnum. These scripts leverage the "id" command to enumerate the privileges of all users present on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Discovery
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1160]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual User Privilege Enumeration via id**

The `id` command in Linux environments is used to display user identity information, including user and group IDs. Adversaries may exploit this command in enumeration scripts to gather extensive user privilege data rapidly, which can aid in lateral movement or privilege escalation. The detection rule identifies suspicious activity by flagging rapid, repeated executions of the `id` command, suggesting potential misuse by scripts like LinPEAS or LinEnum.

**Possible investigation steps**

* Review the alert details to identify the specific host.id and process.parent.entity_id associated with the suspicious activity.
* Examine the parent process of the *id* command executions to determine if it is a known or legitimate process, and check for any unusual or unexpected parent process names or arguments.
* Investigate the timeline of events on the affected host around the time of the alert to identify any other suspicious activities or related processes that may indicate a broader attack or script execution.
* Check the user account associated with the process executions to verify if it has legitimate access and if there are any signs of compromise or misuse.
* Look for any additional indicators of compromise on the host, such as unauthorized file modifications, network connections, or other unusual command executions, to assess the scope of potential malicious activity.

**False positive analysis**

* System management scripts or automated tasks may execute the id command frequently for legitimate purposes. Review the parent process to determine if it is a known management tool or script.
* Software installation or update processes might trigger the rule if they use the id command to verify user permissions. Consider excluding processes with parent names like rpm or similar package managers.
* Custom scripts developed in-house for system monitoring or auditing could inadvertently match the rule’s criteria. Identify these scripts and add exceptions for their parent process entity IDs.
* Security tools or compliance checks that perform regular user enumeration might cause false positives. Verify the source of these tools and exclude them if they are part of a trusted security suite.
* In environments with high user account turnover, scripts that manage user accounts might execute the id command in rapid succession. Evaluate these scripts and exclude them if they are part of routine account management.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes associated with the parent process identified in the alert to halt further enumeration activities.
* Conduct a thorough review of the parent process and its associated scripts to determine if they are legitimate or malicious.
* If malicious activity is confirmed, perform a comprehensive scan of the system for additional indicators of compromise, such as unauthorized user accounts or altered system files.
* Reset credentials for any user accounts that may have been exposed or compromised during the enumeration activity.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.
* Implement enhanced monitoring and logging for similar enumeration activities to improve detection and response capabilities for future incidents.


## Setup [_setup_732]

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


## Rule query [_rule_query_1193]

```js
sequence by host.id, process.parent.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "id" and process.args_count == 2 and
   not (
     process.parent.name in ("rpm", "snarftmp", "quota_copy", "java") or
     process.parent.args : "/var/tmp/rpm-tmp*"
    )] with runs=20
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



