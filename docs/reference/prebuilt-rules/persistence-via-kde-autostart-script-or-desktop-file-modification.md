---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-kde-autostart-script-or-desktop-file-modification.html
---

# Persistence via KDE AutoStart Script or Desktop File Modification [persistence-via-kde-autostart-script-or-desktop-file-modification]

Identifies the creation or modification of a K Desktop Environment (KDE) AutoStart script or desktop file that will execute upon each user logon. Adversaries may abuse this method for persistence.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://userbase.kde.org/System_Settings/Autostart](https://userbase.kde.org/System_Settings/Autostart)
* [https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/)
* [https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/](https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/)
* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 215

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_622]

**Triage and analysis**

**Investigating Persistence via KDE AutoStart Script or Desktop File Modification**

K Desktop Environment (KDE) is a popular graphical desktop environment for Linux systems. It supports AutoStart scripts and desktop files that execute automatically upon user logon.

Adversaries may exploit this feature to maintain persistence on a compromised system by creating or modifying these files.

The detection rule *Persistence via KDE AutoStart Script or Desktop File Modification* is designed to identify such activities by monitoring file events on Linux systems. It specifically targets the creation or modification of files with extensions ".sh" or ".desktop" in various AutoStart directories. By detecting these events, the rule helps security analysts identify potential abuse of KDE AutoStart functionality by malicious actors.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the file that was created or modified.
* !{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE ( path LIKE */home/%/.config/autostart/%.sh* OR path LIKE */home/%/.config/autostart/%.desktop*\nOR path LIKE */root/.config/autostart/%.sh* OR path LIKE */root/.config/autostart/%.desktop* OR path LIKE\n'/home/%/.kde/Autostart/%.sh' OR path LIKE */home/%/.kde/Autostart/%.desktop* OR path LIKE */root/.kde/Autostart/%.sh*\nOR path LIKE */root/.kde/Autostart/%.desktop* OR path LIKE */home/%/.kde4/Autostart/%.sh* OR path LIKE\n'/home/%/.kde4/Autostart/%.desktop' OR path LIKE */root/.kde4/Autostart/%.sh* OR path LIKE\n'/root/.kde4/Autostart/%.desktop' OR path LIKE */home/%/.kde/share/autostart/%.sh* OR path LIKE\n'/home/%/.kde/share/autostart/%.desktop' OR path LIKE */root/.kde/share/autostart/%.sh* OR path LIKE\n'/root/.kde/share/autostart/%.desktop' OR path LIKE */home/%/.kde4/share/autostart/%.sh* OR path LIKE\n'/home/%/.kde4/share/autostart/%.desktop' OR path LIKE */root/.kde4/share/autostart/%.sh* OR path LIKE\n'/root/.kde4/share/autostart/%.desktop' OR path LIKE */home/%/.local/share/autostart/%.sh* OR path LIKE\n'/home/%/.local/share/autostart/%.desktop' OR path LIKE */root/.local/share/autostart/%.sh* OR path LIKE\n'/root/.local/share/autostart/%.desktop' OR path LIKE */home/%/.config/autostart-scripts/%.sh* OR path LIKE\n'/home/%/.config/autostart-scripts/%.desktop' OR path LIKE */root/.config/autostart-scripts/%.sh* OR path LIKE\n'/root/.config/autostart-scripts/%.desktop' OR path LIKE */etc/xdg/autostart/%.sh* OR path LIKE\n'/etc/xdg/autostart/%.desktop' OR path LIKE */usr/share/autostart/%.sh* OR path LIKE */usr/share/autostart/%.desktop* )\n"}}
* !{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE ( path LIKE */home/%/.config/autostart/%.sh* OR\npath LIKE */home/%/.config/autostart/%.desktop* OR path LIKE */root/.config/autostart/%.sh* OR path LIKE\n'/root/.config/autostart/%.desktop' OR path LIKE */home/%/.kde/Autostart/%.sh* OR path LIKE\n'/home/%/.kde/Autostart/%.desktop' OR path LIKE */root/.kde/Autostart/%.sh* OR path LIKE\n'/root/.kde/Autostart/%.desktop' OR path LIKE */home/%/.kde4/Autostart/%.sh* OR path LIKE\n'/home/%/.kde4/Autostart/%.desktop' OR path LIKE */root/.kde4/Autostart/%.sh* OR path LIKE\n'/root/.kde4/Autostart/%.desktop' OR path LIKE */home/%/.kde/share/autostart/%.sh* OR path LIKE\n'/home/%/.kde/share/autostart/%.desktop' OR path LIKE */root/.kde/share/autostart/%.sh* OR path LIKE\n'/root/.kde/share/autostart/%.desktop' OR path LIKE */home/%/.kde4/share/autostart/%.sh* OR path LIKE\n'/home/%/.kde4/share/autostart/%.desktop' OR path LIKE */root/.kde4/share/autostart/%.sh* OR path LIKE\n'/root/.kde4/share/autostart/%.desktop' OR path LIKE */home/%/.local/share/autostart/%.sh* OR path LIKE\n'/home/%/.local/share/autostart/%.desktop' OR path LIKE */root/.local/share/autostart/%.sh* OR path LIKE\n'/root/.local/share/autostart/%.desktop' OR path LIKE */home/%/.config/autostart-scripts/%.sh* OR path LIKE\n'/home/%/.config/autostart-scripts/%.desktop' OR path LIKE */root/.config/autostart-scripts/%.sh* OR path LIKE\n'/root/.config/autostart-scripts/%.desktop' OR path LIKE */etc/xdg/autostart/%.sh* OR path LIKE\n'/etc/xdg/autostart/%.desktop' OR path LIKE */usr/share/autostart/%.sh* OR path LIKE */usr/share/autostart/%.desktop* )\n"}}
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Investigate other alerts associated with the user/host during the past 48 hours.
* Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Investigate whether the altered scripts call other malicious scripts elsewhere on the file system.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* File access, modification, and creation activities.
* Cron jobs, services and other persistence mechanisms.
* !{osquery{"label":"Osquery - Retrieve Crontab Information","query":"SELECT * FROM crontab"}}
* Investigate abnormal behaviors by the subject process/user such as network connections, file modifications, and any other spawned child processes.
* Investigate listening ports and open sockets to look for potential command and control traffic or data exfiltration.
* !{osquery{"label":"Osquery - Retrieve Listening Ports","query":"SELECT pid, address, port, socket, protocol, path FROM listening_ports"}}
* !{osquery{"label":"Osquery - Retrieve Open Sockets","query":"SELECT pid, family, remote_address, remote_port, socket, state FROM process_open_sockets"}}
* Identify the user account that performed the action, analyze it, and check whether it should perform this kind of action.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific User","query":"SELECT * FROM users WHERE username = {user.name}"}}`
* Investigate whether the user is currently logged in and active.
* `!{osquery{"label":"Osquery - Investigate the Account Authentication Status","query":"SELECT * FROM logged_in_users WHERE user = {user.name}"}}`

**False positive analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator who uses cron jobs for administrative purposes, consider adding exceptions for this specific administrator user account.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_403]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).

**Custom Ingest Pipeline**

For versions <8.2, you need to add a custom ingest pipeline to populate `event.ingested` with @timestamp for non-elastic-agent indexes, like auditbeats/filebeat/winlogbeat etc. For more details to add a custom ingest pipeline refer to the [guide](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md).


## Rule query [_rule_query_664]

```js
file where host.os.type == "linux" and event.type != "deletion" and
  file.extension in ("sh", "desktop") and
  file.path :
    (
      "/home/*/.config/autostart/*", "/root/.config/autostart/*",
      "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
      "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
      "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
      "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
      "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
      "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*",
      "/etc/xdg/autostart/*", "/usr/share/autostart/*"
    ) and
    not process.name in (
      "yum", "dpkg", "install", "dnf", "teams", "yum-cron", "dnf-automatic", "docker", "dockerd", "rpm", "pacman",
      "podman", "nautilus", "remmina", "cinnamon-settings.py", "executor", "xfce4-clipman", "jetbrains-toolbox",
      "ansible-admin", "apk"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)



