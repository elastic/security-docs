---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-ssh-it-ssh-worm-downloaded.html
---

# Potential SSH-IT SSH Worm Downloaded [potential-ssh-it-ssh-worm-downloaded]

Identifies processes that are capable of downloading files with command line arguments containing URLs to SSH-IT’s autonomous SSH worm. This worm intercepts outgoing SSH connections every time a user uses ssh.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.thc.org/ssh-it/](https://www.thc.org/ssh-it/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_768]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential SSH-IT SSH Worm Downloaded**

SSH-IT is an autonomous worm that exploits SSH connections to propagate across networks. It hijacks outgoing SSH sessions, allowing adversaries to move laterally within a compromised environment. Attackers often use tools like curl or wget to download the worm from specific URLs. The detection rule identifies these download attempts by monitoring process activities on Linux systems, focusing on command-line arguments that match known malicious URLs, thereby alerting security teams to potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific process name (either curl or wget) and the URL involved in the download attempt to confirm it matches one of the known malicious URLs listed in the query.
* Check the process execution context, including the user account under which the process was executed, to determine if it was initiated by a legitimate user or potentially compromised account.
* Investigate the source IP address and hostname of the affected Linux system to understand its role within the network and assess the potential impact of lateral movement.
* Examine the system’s SSH logs to identify any unusual or unauthorized SSH connections that may indicate further compromise or lateral movement attempts.
* Analyze the network traffic logs for any outbound connections to the identified malicious URLs to confirm whether the download attempt was successful and if any additional payloads were retrieved.
* Review historical alerts and logs for any previous similar activities on the same host or user account to identify patterns or repeated attempts that may indicate a persistent threat.

**False positive analysis**

* Legitimate administrative tasks using curl or wget to download files from the internet may trigger the rule. To manage this, security teams can create exceptions for specific URLs or IP addresses known to be safe and frequently accessed by administrators.
* Automated scripts or cron jobs that use curl or wget to download updates or configuration files from trusted internal or external sources might be flagged. Users can whitelist these scripts or the specific URLs they access to prevent unnecessary alerts.
* Development or testing environments where developers frequently download open-source tools or libraries using curl or wget could generate false positives. Implementing a policy to exclude these environments from the rule or setting up a separate monitoring profile for them can help reduce noise.
* Security tools or monitoring solutions that use curl or wget for health checks or data collection might be mistakenly identified. Identifying these tools and excluding their known benign activities from the rule can help maintain focus on genuine threats.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further lateral movement by the SSH-IT worm.
* Terminate any suspicious processes identified as using curl or wget with the malicious URLs to stop the download and execution of the worm.
* Conduct a thorough scan of the isolated host using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any instances of the SSH-IT worm.
* Review and reset credentials for any SSH accounts that may have been compromised, ensuring the use of strong, unique passwords and considering the implementation of multi-factor authentication (MFA).
* Analyze network logs and SSH access logs to identify any lateral movement or unauthorized access attempts, and take steps to secure any other potentially compromised systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Update firewall and intrusion detection/prevention system (IDS/IPS) rules to block the known malicious URLs and monitor for any future attempts to access them.


## Setup [_setup_495]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_816]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name in ("curl", "wget") and process.args : (
  "https://thc.org/ssh-it/x", "http://nossl.segfault.net/ssh-it-deploy.sh", "https://gsocket.io/x",
  "https://thc.org/ssh-it/bs", "http://nossl.segfault.net/bs"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)



