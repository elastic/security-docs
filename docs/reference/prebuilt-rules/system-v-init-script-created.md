---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-v-init-script-created.html
---

# System V Init Script Created [system-v-init-script-created]

Files that are placed in the /etc/init.d/ directory in Unix can be used to start custom applications, services, scripts or commands during start-up. Init.d has been mostly replaced in favor of Systemd. However, the "systemd-sysv-generator" can convert init.d files to service unit files that run at boot. Adversaries may add or alter files located in the /etc/init.d/ directory to execute malicious code upon boot in order to gain persistence on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/malware-analysis/hiddenwasp-malware-targeting-linux-systems/](https://www.intezer.com/blog/malware-analysis/hiddenwasp-malware-targeting-linux-systems/)
* [https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#8-boot-or-logon-initialization-scripts-rc-scripts](https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#8-boot-or-logon-initialization-scripts-rc-scripts)
* [https://www.cyberciti.biz/faq/how-to-enable-rc-local-shell-script-on-systemd-while-booting-linux-system/](https://www.cyberciti.biz/faq/how-to-enable-rc-local-shell-script-on-systemd-while-booting-linux-system/)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 114

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1062]

**Triage and analysis**

**Investigating System V Init Script Created**

The `/etc/init.d` directory is used in Linux systems to store the initialization scripts for various services and daemons that are executed during system startup and shutdown.

Attackers can abuse files within the `/etc/init.d/` directory to run scripts, commands or malicious software every time a system is rebooted by converting an executable file into a service file through the `systemd-sysv-generator`. After conversion, a unit file is created within the `/run/systemd/generator.late/` directory.

This rule looks for the creation of new files within the `/etc/init.d/` directory. Executable files in these directories will automatically run at boot with root privileges.

[TBC: QUOTE]
**Possible Investigation Steps**

* Investigate the file that was created or modified.
* `!{osquery{"label":"Osquery - Retrieve File Information","query":"SELECT * FROM file WHERE path = {file.path}"}}`
* Investigate whether any other files in the `/etc/init.d/` or `/run/systemd/generator.late/` directories have been altered.
* !{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE path LIKE */etc/init.d/%*"}}
* !{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE path LIKE */etc/init.d/%*\n"}}
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Investigate syslog through the `sudo cat /var/log/syslog | grep 'LSB'` command to find traces of the LSB header of the script (if present). If syslog is being ingested into Elasticsearch, the same can be accomplished through Kibana.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Validate whether this activity is related to planned patches, updates, network administrator activity, or legitimate software installations.
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

**False Positive Analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator who uses init.d for administrative purposes, consider adding exceptions for this specific administrator user account.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Related Rules**

* Suspicious File Creation in /etc for Persistence - 1c84dd64-7e6c-4bad-ac73-a5014ee37042

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Delete the maliciously created service/init.d files or restore it to the original configuration.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_668]

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


## Rule query [_rule_query_1117]

```js
file where host.os.type == "linux" and event.action in ("creation", "file_create_event", "rename", "file_rename_event")
and file.path : "/etc/init.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove", "dpkg-new") or
  file.path like ("/etc/init.d/*beat*", "/etc/init.d/elastic-agent*") or
  process.executable like ("/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*", "/opt/puppetlabs/puppet/bin/ruby") or
  process.name in ("docker-init", "jumpcloud-agent", "crio") or
  process.executable == null or
  process.name in ("executor", "univention-config-registry", "install", "dockerd-entrypoint.sh", "platform-python*", "ssm-agent-worker") or
  (process.name == "ln" and file.path : "/etc/init.d/rc*.d/*") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
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



