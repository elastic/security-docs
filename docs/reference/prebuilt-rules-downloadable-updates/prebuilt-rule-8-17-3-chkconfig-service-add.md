---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-chkconfig-service-add.html
---

# Chkconfig Service Add [prebuilt-rule-8-17-3-chkconfig-service-add]

Detects the use of the chkconfig binary to manually add a service for management by chkconfig. Threat actors may utilize this technique to maintain persistence on a system. When a new service is added, chkconfig ensures that the service has either a start or a kill entry in every runlevel and when the system is rebooted the service file added will run providing long-term persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/](https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Threat: Lightning Framework
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3929]

**Triage and analysis**

**Investigating Chkconfig Service Add**

Service files are configuration files in Linux systems used to define and manage system services. The `Chkconfig` binary can be used to manually add, delete or modify a service.

Malicious actors can leverage services to achieve persistence by creating or modifying service files to execute malicious commands or payloads during system startup. This allows them to maintain unauthorized access, execute additional malicious activities, or evade detection.

This rule monitors the usage of the `chkconfig` binary to manually add a service for management by `chkconfig`, potentially indicating the creation of a persistence mechanism.

[TBC: QUOTE]
**Possible Investigation Steps**

* Investigate the service that was created or modified.
* Investigate the currently enabled system services through the following commands `sudo chkconfig --list | grep on` and `sudo systemctl list-unit-files`.
* Investigate the status of potentially suspicious services through the `chkconfig --list service_name` command.
* Search for the `rc.d` or `init.d` service files that were created or modified, and analyze their contents.
* Investigate whether any other files in any of the available `rc.d` or `init.d` directories have been altered through OSQuery.
* !{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE (path LIKE */etc/init.d/%* OR path LIKE */etc/rc%.d/%*)"}}
* !{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE (path LIKE */etc/init.d/%* OR path LIKE\n'/etc/rc%.d/%')\n"}}
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Investigate syslog through the `sudo cat /var/log/syslog | grep 'LSB'` command to find traces of the LSB header of the script (if present). If syslog is being ingested into Elasticsearch, the same can be accomplished through Kibana.
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
* If this activity is related to a system administrator who uses the `chkconfig` binary for administrative purposes, consider adding exceptions for this specific administrator user account.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Related Rules**

* Suspicious File Creation in /etc for Persistence - 1c84dd64-7e6c-4bad-ac73-a5014ee37042
* Potential Persistence Through Run Control Detected - 0f4d35e4-925e-4959-ab24-911be207ee6f
* Potential Persistence Through init.d Detected - 474fd20e-14cc-49c5-8160-d9ab4ba16c8b
* New Systemd Timer Created - 7fb500fa-8e24-4bd1-9480-2a819352602c
* New Systemd Service Created by Previously Unknown Process - 17b0a495-4d9f-414c-8ad0-92f018b8e001

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Delete the service/timer or restore its original configuration.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_879]

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


## Rule query [_rule_query_4926]

```js
process where host.os.type == "linux" and event.action in ("exec", "exec_event", "start") and
(
  (process.executable : "/usr/sbin/chkconfig" and process.args : "--add") or
  (process.args : "*chkconfig" and process.args : "--add")
) and not (
  process.parent.name in ("rpm", "qualys-scan-util", "qualys-cloud-agent", "update-alternatives") or
  process.parent.args : ("/var/tmp/rpm*", "/var/lib/waagent/*") or
  process.args in ("jexec", "sapinit", "httpd", "dbora")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)



