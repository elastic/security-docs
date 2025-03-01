---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-successful-linux-ftp-brute-force-attack-detected.html
---

# Potential Successful Linux FTP Brute Force Attack Detected [prebuilt-rule-8-17-4-potential-successful-linux-ftp-brute-force-attack-detected]

An FTP (file transfer protocol) brute force attack is a method where an attacker systematically tries different combinations of usernames and passwords to gain unauthorized access to an FTP server, and if successful, the impact can include unauthorized data access, manipulation, or theft, compromising the security and integrity of the server and potentially exposing sensitive information. This rule identifies multiple consecutive authentication failures targeting a specific user account from the same source address and within a short time interval, followed by a successful authentication.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Auditd Manager
* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4321]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Successful Linux FTP Brute Force Attack Detected**

FTP is a protocol used for transferring files between systems, often requiring authentication. Adversaries exploit this by attempting numerous username-password combinations to gain unauthorized access, potentially leading to data breaches. The detection rule identifies a pattern of repeated failed login attempts from a single source, followed by a successful login, indicating a possible brute force attack.

**Possible investigation steps**

* Review the source IP address (auditd.data.addr) involved in the failed and successful login attempts to determine if it is known or associated with previous malicious activity.
* Analyze the timeline of the failed login attempts followed by the successful login to assess the likelihood of a brute force attack, considering the maxspan of 5 seconds.
* Check the user account (related.user) targeted by the login attempts to determine if it is a high-value account or has been involved in previous security incidents.
* Investigate the host (host.id) where the login attempts occurred to identify any other suspicious activities or anomalies around the time of the alert.
* Correlate the detected activity with other logs or alerts from the same time period to identify potential lateral movement or further compromise within the network.

**False positive analysis**

* Repeated failed logins from automated scripts or monitoring tools can trigger false positives. Identify and whitelist IP addresses of known internal systems or services that perform regular FTP checks.
* Users with incorrect credentials saved in FTP clients may cause multiple failed attempts before a successful login. Educate users on updating saved credentials and consider excluding specific user accounts from the rule if they frequently trigger alerts.
* Scheduled tasks or cron jobs that attempt to connect with outdated credentials can result in false positives. Review and update scheduled tasks to ensure they use current credentials, and exclude these tasks from monitoring if they are non-threatening.
* High-volume legitimate FTP traffic from trusted partners or vendors might mimic brute force patterns. Establish a list of trusted external IP addresses and exclude them from the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Reset the compromised user account’s password and any other accounts that may have been accessed using the same credentials.
* Review and analyze the logs from the affected system to identify any unauthorized changes or data access that occurred during the breach.
* Implement IP blocking or rate limiting for the source address identified in the alert to prevent further brute force attempts from the same origin.
* Conduct a thorough security assessment of the FTP server configuration to ensure it adheres to best practices, such as disabling anonymous access and enforcing strong password policies.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems were affected.
* Enhance monitoring and alerting for similar brute force patterns by ensuring that detection rules are tuned to capture variations in attack techniques.


## Setup [_setup_1172]

**Setup**

This rule requires data coming in from one of the following integrations: - Auditbeat - Auditd Manager

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://docs/reference/auditbeat/setting-up-running.md).

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" on a Linux System:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule no additional audit rules are required to be added to the integration.


## Rule query [_rule_query_5313]

```js
sequence by host.id, auditd.data.addr, related.user with maxspan=5s
  [authentication where host.os.type == "linux" and event.action == "authenticated" and
   auditd.data.terminal == "ftp" and event.outcome == "failure" and auditd.data.addr != null and
   auditd.data.addr != "0.0.0.0" and auditd.data.addr != "::"] with runs=10
  [authentication where host.os.type == "linux" and event.action  == "authenticated" and
   auditd.data.terminal == "ftp" and event.outcome == "success" and auditd.data.addr != null and
   auditd.data.addr != "0.0.0.0" and auditd.data.addr != "::"] | tail 1
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Password Guessing
    * ID: T1110.001
    * Reference URL: [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)

* Sub-technique:

    * Name: Password Spraying
    * ID: T1110.003
    * Reference URL: [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)



