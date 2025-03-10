---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-systemd-timer-created.html
---

# Systemd Timer Created [prebuilt-rule-8-17-4-systemd-timer-created]

Detects the creation of a systemd timer within any of the default systemd timer directories. Systemd timers can be used by an attacker to gain persistence, by scheduling the execution of a command or script. Similarly to cron/at, systemd timers can be set up to execute on boot time, or on a specific point in time, which allows attackers to regain access in case the connection to the infected asset was lost.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://opensource.com/article/20/7/systemd-timers](https://opensource.com/article/20/7/systemd-timers)
* [https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/)
* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 16

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4499]

**Triage and analysis**

**Investigating Systemd Timer Created**

Systemd timers are used for scheduling and automating recurring tasks or services on Linux systems.

Attackers can leverage systemd timers to run scripts, commands, or malicious software at system boot or on a set time interval by creating a systemd timer and a corresponding systemd service file.

This rule monitors the creation of new systemd timer files, potentially indicating the creation of a persistence mechanism.

[TBC: QUOTE]
**Possible Investigation Steps**

* Investigate the timer file that was created or modified.
* `!{osquery{"label":"Osquery - Retrieve File Information","query":"SELECT * FROM file WHERE path = {file.path}"}}`
* Investigate the currently enabled systemd timers through the following command `sudo systemctl list-timers`.
* Search for the systemd service file named similarly to the timer that was created.
* Investigate whether any other files in any of the available systemd directories have been altered through OSQuery.
* `!{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE (path LIKE */etc/systemd/system/%* OR path LIKE */usr/local/lib/systemd/system/%* OR path LIKE\n'/lib/systemd/system/%' OR path LIKE */usr/lib/systemd/system/%* OR path LIKE\n'/home/{user.name}/.config/systemd/user/%' OR path LIKE */home/{user.name}/.local/share/systemd/user/%* OR path LIKE\n'/root/.config/systemd/user/%' OR path LIKE */root/.local/share/systemd/user/%* OR path LIKE */etc/systemd/user/%* OR\npath LIKE */usr/lib/systemd/user/%*)\n"}}`
* `!{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE ( path LIKE */etc/systemd/system/%* OR path LIKE\n'/usr/local/lib/systemd/system/%' OR path LIKE */lib/systemd/system/%* OR path LIKE */usr/lib/systemd/system/%* OR path\nLIKE */home/{user.name}/.config/systemd/user/%* OR path LIKE */home/{user.name}/.local/share/systemd/user/%* OR path\nLIKE */root/.config/systemd/user/%* OR path LIKE */root/.local/share/systemd/user/%* OR path LIKE */etc/systemd/user/%*\nOR path LIKE */usr/lib/systemd/user/%*)\n"}}`
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

**False Positive Analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator who uses systemd timers for administrative purposes, consider adding exceptions for this specific administrator user account.
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
* Delete the service/timer or restore its original configuration.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1333]

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


## Rule query [_rule_query_5491]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
  "/etc/systemd/system/*", "/etc/systemd/user/*", "/usr/local/lib/systemd/system/*",
  "/lib/systemd/system/*", "/usr/lib/systemd/system/*", "/usr/lib/systemd/user/*",
  "/home/*/.config/systemd/user/*", "/home/*/.local/share/systemd/user/*",
  "/root/.config/systemd/user/*", "/root/.local/share/systemd/user/*"
) and file.extension == "timer" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/kaniko/executor"
  ) or
  process.name like (
    "python*", "crio", "apt-get", "install", "snapd", "cloudflared", "sshd", "convert-usrmerge", "docker-init",
    "google_metadata_script_runner", "ssm-agent-worker", "pacman", "convert2rhel", "platform-python"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
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

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Systemd Timers
    * ID: T1053.006
    * Reference URL: [https://attack.mitre.org/techniques/T1053/006/](https://attack.mitre.org/techniques/T1053/006/)



