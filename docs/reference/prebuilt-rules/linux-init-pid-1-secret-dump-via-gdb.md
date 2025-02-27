---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-init-pid-1-secret-dump-via-gdb.html
---

# Linux init (PID 1) Secret Dump via GDB [linux-init-pid-1-secret-dump-via-gdb]

This rule monitors for the potential memory dump of the init process (PID 1) through gdb. Attackers may leverage memory dumping techniques to attempt secret extraction from privileged processes. Tools that display this behavior include "truffleproc" and "bash-memory-dump". This behavior should not happen by default, and should be investigated thoroughly.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/controlplaneio/truffleproc](https://github.com/controlplaneio/truffleproc)
* [https://github.com/hajzer/bash-memory-dump](https://github.com/hajzer/bash-memory-dump)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_480]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Linux init (PID 1) Secret Dump via GDB**

In Linux, the init process (PID 1) is the first process started by the kernel and is responsible for initializing the system. Adversaries may exploit debugging tools like GDB to dump memory from this process, potentially extracting sensitive information. The detection rule identifies suspicious GDB executions targeting PID 1, flagging unauthorized memory access attempts for further investigation.

**Possible investigation steps**

* Review the alert details to confirm the process name is "gdb" and the process arguments include "--pid" or "-p" with a target of PID "1".
* Check the user account associated with the gdb process execution to determine if it is authorized to perform debugging tasks on the system.
* Investigate the parent process of the gdb execution to understand how it was initiated and whether it was part of a legitimate workflow or script.
* Examine system logs around the time of the alert to identify any other suspicious activities or related events that might indicate a broader attack.
* Assess the system for any unauthorized changes or anomalies, such as new user accounts, modified configurations, or unexpected network connections.
* If possible, capture and analyze memory dumps or other forensic artifacts to identify any sensitive information that may have been accessed or exfiltrated.

**False positive analysis**

* System administrators or developers may use GDB for legitimate debugging purposes on the init process. To handle this, create exceptions for known maintenance windows or specific user accounts that are authorized to perform such actions.
* Automated scripts or monitoring tools might inadvertently trigger this rule if they include GDB commands targeting PID 1 for health checks. Review and adjust these scripts to avoid unnecessary memory access or exclude them from the rule if they are verified as safe.
* Security tools or forensic analysis software might use GDB as part of their operations. Identify these tools and whitelist their processes to prevent false positives while ensuring they are from trusted sources.
* Training or testing environments may simulate attacks or debugging scenarios involving GDB and PID 1. Exclude these environments from the rule to avoid noise, ensuring they are isolated from production systems.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate the suspicious gdb process targeting PID 1 to stop any ongoing memory dumping activity.
* Conduct a thorough review of system logs and process execution history to identify any additional unauthorized access attempts or related suspicious activities.
* Change all credentials and secrets that may have been exposed or accessed during the memory dump, focusing on those used by the init process and other privileged accounts.
* Implement stricter access controls and monitoring for debugging tools like gdb, ensuring only authorized personnel can execute such tools on critical systems.
* Escalate the incident to the security operations team for a comprehensive investigation and to determine if further forensic analysis is required.
* Update and enhance detection rules and monitoring systems to better identify and alert on similar unauthorized memory access attempts in the future.


## Setup [_setup_309]

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


## Rule query [_rule_query_517]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name == "gdb" and process.args in ("--pid", "-p") and process.args == "1"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Proc Filesystem
    * ID: T1003.007
    * Reference URL: [https://attack.mitre.org/techniques/T1003/007/](https://attack.mitre.org/techniques/T1003/007/)



