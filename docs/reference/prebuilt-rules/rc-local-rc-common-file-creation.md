---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/rc-local-rc-common-file-creation.html
---

# rc.local/rc.common File Creation [rc-local-rc-common-file-creation]

This rule monitors the creation/alteration of the rc.local/rc.common file. The /etc/rc.local file is used to start custom applications, services, scripts or commands during start-up. The rc.local file has mostly been replaced by Systemd. However, through the "systemd-rc-local-generator", rc.local files can be converted to services that run at boot. Adversaries may alter rc.local/rc.common to execute malicious code at start-up, and gain persistence onto the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

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
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 115

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1214]

**Triage and analysis**

**Investigating rc.local/rc.common File Creation**

The `rc.local` file executes custom commands or scripts during system startup on Linux systems. `rc.local` has been deprecated in favor of the use of `systemd services`, and more recent Unix distributions no longer leverage this method of on-boot script execution.

There might still be users that use `rc.local` in a benign matter, so investigation to see whether the file is malicious is vital.

Detection alerts from this rule indicate the creation of a new `/etc/rc.local` file.

[TBC: QUOTE]
**Possible Investigation Steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate the file that was created or modified.
* `!{osquery{"label":"Osquery - Retrieve File Information","query":"SELECT * FROM file WHERE path = {file.path}"}}`
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Investigate whether the `/lib/systemd/system/rc-local.service` and `/run/systemd/generator/multi-user.target.wants/rc-local.service` files were created through the `systemd-rc-local-generator` located at `/usr/lib/systemd/system-generators/systemd-rc-local-generator`.
* !{osquery{"label":"Osquery - Retrieve rc-local.service File Information","query":"SELECT * FROM file WHERE (path = */run/systemd/generator/multi-user.target.wants/rc-local.service* OR path =\n'/run/systemd/generator/multi-user.target.wants/rc-local.service')\n"}}
* In case the file is not present here, `sudo systemctl status rc-local` can be executed to find the location of the rc-local unit file.
* If `rc-local.service` is found, manual investigation is required to check for the rc script execution. Systemd will generate syslogs in case of the execution of the rc-local service. `sudo cat /var/log/syslog | grep "rc-local.service|/etc/rc.local Compatibility"` can be executed to check for the execution of the service.
* If logs are found, it’s likely that the contents of the `rc.local` file have been executed. Analyze the logs. In case several syslog log files are available, use a wildcard to search through all of the available logs.
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
* If this activity is related to a system administrator who uses `rc.local` for administrative purposes, consider adding exceptions for this specific administrator user account.
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
* Delete the `service/rc.local` files or restore their original configuration.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_762]

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


## Rule query [_rule_query_1244]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path in ("/etc/rc.local", "/etc/rc.common") and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  process.name in ("ssm-agent-worker", "convert2rhel", "platform-python*") or
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

* Sub-technique:

    * Name: RC Scripts
    * ID: T1037.004
    * Reference URL: [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)



