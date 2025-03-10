---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/shared-object-created-or-changed-by-previously-unknown-process.html
---

# Shared Object Created or Changed by Previously Unknown Process [shared-object-created-or-changed-by-previously-unknown-process]

This rule monitors the creation of shared object files by previously unknown processes. The creation of a shared object file involves compiling code into a dynamically linked library that can be loaded by other programs at runtime. While this process is typically used for legitimate purposes, malicious actors can leverage shared object files to execute unauthorized code, inject malicious functionality into legitimate processes, or bypass security controls. This allows malware to persist on the system, evade detection, and potentially compromise the integrity and confidentiality of the affected system and its data.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://threatpost.com/sneaky-malware-backdoors-linux/180158/](https://threatpost.com/sneaky-malware-backdoors-linux/180158/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_927]

**Triage and analysis**

**Investigating Shared Object Created or Changed by Previously Unknown Process**

A shared object file is a compiled library file (typically with a .so extension) that can be dynamically linked to executable programs at runtime, allowing for code reuse and efficient memory usage. The creation of a shared object file involves compiling code into a dynamically linked library that can be loaded by other programs at runtime.

Malicious actors can leverage shared object files to execute unauthorized code, inject malicious functionality into legitimate processes, or bypass security controls. This allows malware to persist on the system, evade detection, and potentially compromise the integrity and confidentiality of the affected system and its data.

This rule monitors the creation of shared object files by previously unknown processes through the usage of the new terms rule type.

[TBC: QUOTE]
**Possible Investigation Steps**

* Investigate the shared object that was created or modified through OSQuery.
* `!{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE path = {file.path}\n"}}`
* `!{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE path = {file.path}\n"}}`
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

**False Positive Analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator that performed these actions for administrative purposes, consider adding exceptions for this specific administrator user account.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Response and remediation**

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


## Setup [_setup_583]

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


## Rule query [_rule_query_987]

```js
host.os.type:linux and event.action:(creation or file_create_event or file_rename_event or rename) and
file.path:(/dev/shm/* or /usr/lib/*) and file.extension:so and process.name:* and not (
  process.name:(
    "dockerd" or "dpkg" or "rpm" or "snapd" or "yum" or "vmis-launcher" or "pacman" or "apt-get" or "dnf" or "podman" or
    platform-python* or "dnf-automatic" or "unattended-upgrade" or "apk" or "snap-update-ns" or "install" or "exe" or
    "systemd" or "root" or "sshd" or "pip" or "jlink" or python* or "update-alternatives" or pip* or
    "installer.bin.inst" or "uninstall-bin" or "linux_agent.inst" or crio or ssm-agent-worker or packagekitd
  ) or
  (process.name:vmware-install.pl and file.path:/usr/lib/vmware-tools/*) or
  process.executable : (/dev/fd/* or "/" or "/kaniko/executor" or "/usr/bin/buildah")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



