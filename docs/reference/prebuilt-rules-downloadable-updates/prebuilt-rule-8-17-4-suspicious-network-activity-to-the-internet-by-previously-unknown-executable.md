---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-network-activity-to-the-internet-by-previously-unknown-executable.html
---

# Suspicious Network Activity to the Internet by Previously Unknown Executable [prebuilt-rule-8-17-4-suspicious-network-activity-to-the-internet-by-previously-unknown-executable]

This rule monitors for network connectivity to the internet from a previously unknown executable located in a suspicious directory. An alert from this rule can indicate the presence of potentially malicious activity, such as the execution of unauthorized or suspicious processes attempting to establish connections to unknown or suspicious destinations such as a command and control server. Detecting and investigating such behavior can help identify and mitigate potential security threats, protecting the system and its data from potential compromise.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-59m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 12

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4312]

**Triage and analysis**

**Investigating Suspicious Network Activity to the Internet by Previously Unknown Executable**

After being installed, malware will often call out to its command and control server to receive further instructions by its operators.

This rule leverages the new terms rule type to detect previously unknown processes, initiating network connections to external IP-addresses.

[TBC: QUOTE]
**Possible investigation steps**

* Identify any signs of suspicious network activity or anomalies that may indicate malicious behavior. This could include unexpected traffic patterns or unusual network behavior.
* Investigate listening ports and open sockets to look for potential malicious processes, reverse shells or data exfiltration.
* !{osquery{"label":"Osquery - Retrieve Listening Ports","query":"SELECT pid, address, port, socket, protocol, path FROM listening_ports"}}
* !{osquery{"label":"Osquery - Retrieve Open Sockets","query":"SELECT pid, family, remote_address, remote_port, socket, state FROM process_open_sockets"}}
* Identify the user account that performed the action, analyze it, and check whether it should perform this kind of action.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific User","query":"SELECT * FROM users WHERE username = {user.name}"}}`
* Investigate whether the user is currently logged in and active.
* `!{osquery{"label":"Osquery - Investigate the Account Authentication Status","query":"SELECT * FROM logged_in_users WHERE user = {user.name}"}}`
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* !{osquery{"label":"Osquery - Retrieve Process Info","query":"SELECT name, cmdline, parent, path, uid FROM processes"}}
* Investigate other alerts associated with the user/host during the past 48 hours.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* File access, modification, and creation activities.

**Related rules**

* Network Activity Detected via cat - afd04601-12fc-4149-9b78-9c3f8fe45d39

**False positive analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors, such as reverse shells, reverse proxies, or droppers, that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1164]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat - Filebeat - Packetbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete “Setup and Run Filebeat” information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Packetbeat Setup**

Packetbeat is a real-time network packet analyzer that you can use for application monitoring, performance analytics, and threat detection. Packetbeat works by capturing the network traffic between your application servers, decoding the application layer protocols (HTTP, MySQL, Redis, and so on), correlating the requests with the responses, and recording the interesting fields for each transaction.

**The following steps should be executed in order to add the Packetbeat on a  Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/packetbeat/setup-repositories.md).
* To run Packetbeat on Docker follow the setup instructions in the [helper guide](beats://reference/packetbeat/running-on-docker.md).
* For quick start information for Packetbeat refer to the [helper guide](beats://reference/packetbeat/packetbeat-installation-configuration.md).
* For complete “Setup and Run Packetbeat” information refer to the [helper guide](beats://reference/packetbeat/setting-up-running.md).


## Rule query [_rule_query_5304]

```js
host.os.type:linux and event.category:network and event.action:(connection_attempted or ipv4_connection_attempt_event) and
process.executable : (
  /etc/crontab or /etc/rc.local or ./* or /boot/* or /dev/shm/* or /etc/cron.*/* or /etc/init.d/* or /etc/rc*.d/* or
  /etc/update-motd.d/* or /home/*/.* or /tmp/* or /usr/lib/update-notifier/* or /var/log/* or /var/tmp/*
) and process.name : * and
not (
  process.executable : (
    /tmp/newroot/* or /tmp/snap.rootfs* or /etc/cron.hourly/BitdefenderRedline or /tmp/go-build* or /srv/snp/docker/* or
    /run/containerd/* or /tmp/.mount* or /run/k3s/containerd/* or /tmp/selenium* or /tmp/tmp.*/juliainstaller or
    /tmp/.criu.mntns* or /home/*/.local/share/containers/* or /etc/update-motd.d/*
  ) or
  source.ip:(10.0.0.0/8 or 127.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16) or
  process.name : (
    apt or chrome or curl or dnf or dockerd or dpkg or firefox-bin or git-remote-https or java or kite-update or
    kited or node or rpm or saml2aws or selenium-manager or solana-validator or wget or yum or ansible* or aws* or
    php* or pip* or python* or steam* or terraform* or filebeat or apk or cursor or http
  ) or
  destination.ip:(
    0.0.0.0 or 10.0.0.0/8 or 100.64.0.0/10 or 127.0.0.0/8 or 169.254.0.0/16 or 172.16.0.0/12 or 192.0.0.0/24 or
    192.0.0.0/29 or 192.0.0.10/32 or 192.0.0.170/32 or 192.0.0.171/32 or 192.0.0.8/32 or 192.0.0.9/32 or 192.0.2.0/24 or
    192.168.0.0/16 or 192.175.48.0/24 or 192.31.196.0/24 or 192.52.193.0/24 or 192.88.99.0/24 or 198.18.0.0/15 or
    198.51.100.0/24 or 203.0.113.0/24 or 224.0.0.0/4 or 240.0.0.0/4 or "::1" or "FE80::/10" or "FF00::/8"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



