---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/pluggable-authentication-module-pam-version-discovery.html
---

# Pluggable Authentication Module (PAM) Version Discovery [pluggable-authentication-module-pam-version-discovery]

This rule detects PAM version discovery activity on Linux systems. PAM version discovery can be an indication of an attacker attempting to backdoor the authentication process through malicious PAM modules.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.group-ib.com/blog/pluggable-authentication-module/](https://www.group-ib.com/blog/pluggable-authentication-module/)
* [https://embracethered.com/blog/posts/2022/post-exploit-pam-ssh-password-grabbing/](https://embracethered.com/blog/posts/2022/post-exploit-pam-ssh-password-grabbing/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Persistence
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_636]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Pluggable Authentication Module (PAM) Version Discovery**

Pluggable Authentication Modules (PAM) provide a flexible mechanism for authenticating users on Linux systems. Adversaries may exploit PAM by discovering its version to identify vulnerabilities or backdoor the authentication process with malicious modules. The detection rule identifies suspicious processes querying PAM-related packages, indicating potential reconnaissance or tampering attempts, thus alerting security teams to possible threats.

**Possible investigation steps**

* Review the process details to confirm the presence of suspicious activity, focusing on processes with names "dpkg", "dpkg-query", or "rpm" and their arguments "libpam-modules" or "pam".
* Check the user account associated with the process to determine if it is a legitimate user or potentially compromised.
* Investigate the parent process to understand the origin of the command execution and assess if it aligns with normal user behavior.
* Analyze recent login attempts and authentication logs to identify any unusual patterns or failed attempts that may indicate unauthorized access attempts.
* Correlate this activity with other alerts or logs from the same host to identify if there are additional indicators of compromise or related suspicious activities.

**False positive analysis**

* Routine system updates or package management activities may trigger the rule when legitimate processes like dpkg or rpm query PAM-related packages. To manage this, consider creating exceptions for known maintenance windows or trusted administrative scripts.
* Automated configuration management tools, such as Ansible or Puppet, might execute commands that match the rule’s criteria. Identify these tools and exclude their processes from triggering alerts by specifying their execution context.
* Security compliance checks or vulnerability assessments often involve querying system packages, including PAM. If these are regularly scheduled and verified, whitelist the associated processes to prevent unnecessary alerts.
* Developers or system administrators testing PAM configurations might inadvertently trigger the rule. Establish a protocol for notifying the security team of such activities in advance, allowing for temporary exceptions during testing periods.
* Custom scripts used for system monitoring or auditing may include commands that match the rule. Review these scripts and, if deemed safe, add them to an exclusion list to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those involving *dpkg*, *dpkg-query*, or *rpm* with arguments related to PAM.
* Conduct a thorough review of PAM configuration files and modules on the affected system to identify and remove any unauthorized or malicious modifications.
* Restore any compromised PAM modules from a known good backup to ensure the integrity of the authentication process.
* Monitor for any additional suspicious activity on the affected system and related systems, focusing on unusual authentication attempts or process executions.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for PAM-related activities across the network to detect similar threats in the future.


## Setup [_setup_405]

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


## Rule query [_rule_query_678]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.parent.name != null and
  (
    (process.name in ("dpkg", "dpkg-query") and process.args == "libpam-modules") or
    (process.name == "rpm" and process.args == "pam")
  ) and
not process.parent.name in ("dcservice", "inspectorssmplugin")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



