---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-spawned-from-message-of-the-day-motd.html
---

# Process Spawned from Message-of-the-Day (MOTD) [prebuilt-rule-8-17-4-process-spawned-from-message-of-the-day-motd]

Message of the day (MOTD) is the message that is presented to the user when a user connects to a Linux server via SSH or a serial connection. Linux systems contain several default MOTD files located in the "/etc/update-motd.d/" directory. These scripts run as the root user every time a user connects over SSH or a serial connection. Adversaries may create malicious MOTD files that grant them persistence onto the target every time a user connects to the system by executing a backdoor script or command. This rule detects the execution of potentially malicious processes through the MOTD utility.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#10-boot-or-logon-initialization-scripts-motd](https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#10-boot-or-logon-initialization-scripts-motd)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4473]

**Triage and analysis**

**Investigating Process Spawned from Message-of-the-Day (MOTD)**

The message-of-the-day (MOTD) is used to display a customizable system-wide message or information to users upon login in Linux.

Attackers can abuse message-of-the-day (motd) files to run scripts, commands or malicious software every time a user connects to a system over SSH or a serial connection, by creating a new file within the `/etc/update-motd.d/` directory. Files in these directories will automatically run with root privileges when they are made executable.

This rule identifies the execution of potentially malicious processes from a MOTD script, which is not likely to occur as default benign behavior.

[TBC: QUOTE]
**Possible Investigation Steps**

* Investigate the file that was created or modified from which the suspicious process was executed.
* `!{osquery{"label":"Osquery - Retrieve File Information","query":"SELECT * FROM file WHERE path = {file.path}"}}`
* Investigate whether any other files in the `/etc/update-motd.d/` directory have been altered.
* !{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE path LIKE */etc/update-motd.d/%*"}}
* !{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE path LIKE */etc/update-motd.d/%*\n"}}
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate whether the altered scripts call other malicious scripts elsewhere on the file system.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* File access, modification, and creation activities.
* Cron jobs, services, and other persistence mechanisms.
* !{osquery{"label":"Osquery - Retrieve Crontab Information","query":"SELECT * FROM crontab"}}

**Related Rules**

* Message-of-the-Day (MOTD) File Creation - 96d11d31-9a79-480f-8401-da28b194608f

**False positive analysis**

* This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Delete the MOTD files or restore them to the original configuration.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1315]

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


## Rule query [_rule_query_5465]

```js
process where event.type == "start" and host.os.type == "linux" and event.action : ("exec", "exec_event", "start") and
  process.parent.executable : "/etc/update-motd.d/*" and
  (
    (
      process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
      (
        process.args : ("-i", "-l") or
        (process.parent.name == "socat" and process.parent.args : "*exec*")
      )
    ) or
    (
      process.name : ("nc", "ncat", "netcat", "nc.openbsd") and process.args_count >= 3 and
      not process.args : ("-*z*", "-*l*")
    ) or
    (
      process.name : "python*" and process.args : "-c" and process.args : (
        "*import*pty*spawn*", "*import*subprocess*call*"
      )
    ) or
    (
      process.name : "perl*" and process.args : "-e" and process.args : "*socket*" and process.args : (
        "*exec*", "*system*"
      )
    ) or
    (
      process.name : "ruby*" and process.args : ("-e", "-rsocket") and process.args : (
        "*TCPSocket.new*", "*TCPSocket.open*"
      )
    ) or
    (
      process.name : "lua*" and process.args : "-e" and process.args : "*socket.tcp*" and process.args : (
        "*io.popen*", "*os.execute*"
      )
    ) or
    (process.name : "php*" and process.args : "-r" and process.args : "*fsockopen*" and process.args : "*/bin/*sh*") or
    (process.name : ("awk", "gawk", "mawk", "nawk") and process.args : "*/inet/tcp/*") or
    (process.name in ("openssl", "telnet")) or
    (
      process.args : (
        "./*", "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*", "/run/*", "/srv/*",
        "/tmp/*", "/var/tmp/*", "/var/log/*", "/opt/*"
      ) and process.args_count == 1
    )
  ) and
  not (
    process.parent.args == "--force" or
    process.args in ("/usr/games/lolcat", "/usr/bin/screenfetch") or
    process.parent.name == "system-crash-notification"
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



