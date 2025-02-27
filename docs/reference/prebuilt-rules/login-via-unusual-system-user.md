---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/login-via-unusual-system-user.html
---

# Login via Unusual System User [login-via-unusual-system-user]

This rule identifies successful logins by system users that are uncommon to authenticate. These users have `nologin` set by default, and must be modified to allow SSH access. Adversaries may backdoor these users to gain unauthorized access to the system.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-system.auth-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/](https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/)
* [https://x.com/RFGroenewoud/status/1875112050218922010](https://x.com/RFGroenewoud/status/1875112050218922010)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: System
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_484]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Login via Unusual System User**

In Linux environments, system users typically have restricted login capabilities to prevent unauthorized access. These accounts, often set with `nologin`, are not meant for interactive sessions. Adversaries may exploit these accounts by altering their configurations to enable SSH access, thus bypassing standard security measures. The detection rule identifies successful logins by these uncommon system users, flagging potential unauthorized access attempts for further investigation.

**Possible investigation steps**

* Review the login event details to identify the specific system user account involved in the successful login, focusing on the user.name field.
* Check the system logs for any recent changes to the user account’s configuration, particularly modifications that might have enabled SSH access for accounts typically set with nologin.
* Investigate the source IP address associated with the login event to determine if it is known or suspicious, and assess whether it aligns with expected access patterns.
* Examine the timeline of events leading up to and following the login to identify any unusual activities or patterns that could indicate malicious behavior.
* Verify if there are any other successful login attempts from the same source IP or involving other system user accounts, which could suggest a broader compromise.
* Consult with system administrators to confirm whether any legitimate changes were made to the system user account’s login capabilities and document any authorized modifications.

**False positive analysis**

* System maintenance tasks may require temporary login access for system users. Verify if the login corresponds with scheduled maintenance and consider excluding these events during known maintenance windows.
* Automated scripts or services might use system accounts for legitimate purposes. Identify these scripts and whitelist their associated activities to prevent false alerts.
* Some system users might be configured for specific applications that require login capabilities. Review application requirements and exclude these users if their access is deemed necessary and secure.
* In environments with custom configurations, certain system users might be intentionally modified for operational needs. Document these changes and adjust the detection rule to exclude these known modifications.
* Regularly review and update the list of system users in the detection rule to ensure it reflects the current environment and operational requirements, minimizing unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any active sessions associated with the unusual system user accounts identified in the alert to disrupt ongoing unauthorized access.
* Review and revert any unauthorized changes to the system user accounts, such as modifications to the shell configuration that enabled login capabilities.
* Conduct a thorough audit of the system for any additional unauthorized changes or backdoors, focusing on SSH configurations and user account settings.
* Reset passwords and update authentication mechanisms for all system user accounts to prevent further exploitation.
* Implement additional monitoring and alerting for any future login attempts by system users, ensuring rapid detection and response to similar threats.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_310]

**Setup**

This rule requires data coming in from Filebeat.

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete “Setup and Run Filebeat” information refer to the [helper guide](beats://docs/reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the “Filebeat System Module” to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_521]

```js
authentication where host.os.type == "linux" and event.action in ("ssh_login", "user_login") and
user.name in (
  "deamon", "bin", "sys", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
  "list", "irc", "gnats", "nobody", "systemd-timesync", "systemd-network", "systemd-resolve", "messagebus",
  "avahi", "sshd", "dnsmasq"
) and event.outcome == "success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Users
    * ID: T1564.002
    * Reference URL: [https://attack.mitre.org/techniques/T1564/002/](https://attack.mitre.org/techniques/T1564/002/)



