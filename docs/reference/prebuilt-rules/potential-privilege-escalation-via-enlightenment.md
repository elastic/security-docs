---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-enlightenment.html
---

# Potential Privilege Escalation via Enlightenment [potential-privilege-escalation-via-enlightenment]

Identifies an attempt to exploit a local privilege escalation CVE-2022-37706 via a flaw in Linux window manager package Enlightenment. enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://ubuntu.com/security/CVE-2022-37706](https://ubuntu.com/security/CVE-2022-37706)
* [https://www.exploit-db.com/exploits/51180](https://www.exploit-db.com/exploits/51180)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_735]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Enlightenment**

Enlightenment, a Linux window manager, can be exploited for privilege escalation due to a flaw in its setuid root configuration. Attackers may exploit this by manipulating pathnames, gaining unauthorized root access. The detection rule identifies suspicious execution of *enlightenment_sys* with specific arguments and subsequent UID changes to root, flagging potential exploitation attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of the process "enlightenment_sys" with the specified arguments ("/bin/mount/", "-o", "noexec", "nosuid", "nodev", "uid=*") on a Linux host.
* Check the process execution timeline to verify if the suspicious "enlightenment_sys" execution was followed by a UID change to root (user.id == "0") within a 5-second window.
* Investigate the host.id and process.parent.entity_id to identify the parent process and determine if it was initiated by a legitimate user or service.
* Examine the system logs around the time of the alert to identify any other unusual activities or related processes that might indicate a broader attack or exploitation attempt.
* Assess the affected system for any unauthorized changes or signs of compromise, focusing on privilege escalation indicators and potential persistence mechanisms.
* Review user access logs and permissions to determine if the user associated with the process had legitimate reasons to execute "enlightenment_sys" with elevated privileges.
* Consider isolating the affected system to prevent further exploitation and begin remediation steps, such as applying patches or configuration changes to mitigate the vulnerability.

**False positive analysis**

* Legitimate administrative tasks using enlightenment_sys may trigger the rule. Review the context of the execution, such as the user and the specific arguments used, to determine if the activity is authorized.
* Automated scripts or system maintenance processes that involve enlightenment_sys with similar arguments might be flagged. Identify these scripts and consider excluding them by specifying their process hashes or paths in the detection rule.
* System updates or package installations that temporarily change UID to root could be misinterpreted as exploitation attempts. Monitor these activities and whitelist known update processes to prevent false alerts.
* Custom user applications that interact with enlightenment_sys for legitimate purposes may cause false positives. Evaluate these applications and, if deemed safe, add them to an exception list based on their unique identifiers.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes related to *enlightenment_sys* that are running with elevated privileges to stop ongoing exploitation.
* Conduct a thorough review of system logs to identify any unauthorized changes or access patterns, focusing on UID changes to root.
* Revoke any unauthorized access or privileges granted during the exploitation, ensuring that only legitimate users have root access.
* Apply the latest security patches and updates to the Enlightenment package, specifically upgrading to version 0.25.4 or later to mitigate the vulnerability.
* Implement file integrity monitoring to detect unauthorized changes to critical system files and configurations in the future.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_470]

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


## Rule query [_rule_query_782]

```js
sequence by host.id, process.parent.entity_id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
    process.name == "enlightenment_sys" and process.args in ("/bin/mount/", "-o","noexec","nosuid","nodev","uid=*") ]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and user.id == "0"]
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



