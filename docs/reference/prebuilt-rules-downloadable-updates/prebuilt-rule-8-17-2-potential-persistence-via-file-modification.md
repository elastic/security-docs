---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-potential-persistence-via-file-modification.html
---

# Potential Persistence via File Modification [prebuilt-rule-8-17-2-potential-persistence-via-file-modification]

This rule leverages the File Integrity Monitoring (FIM) integration to detect file modifications of files that are commonly used for persistence on Linux systems. The rule detects modifications to files that are commonly used for cron jobs, systemd services, message-of-the-day (MOTD), SSH configurations, shell configurations, runtime control, init daemon, passwd/sudoers/shadow files, Systemd udevd, and XDG/KDE autostart entries. To leverage this rule, the paths specified in the query need to be added to the FIM policy in the Elastic Security app.

**Rule type**: eql

**Rule indices**:

* logs-fim.event-*
* auditbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Credential Access
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Data Source: File Integrity Monitoring

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_788]

**Setup**

This rule requires data coming in from the Elastic File Integrity Monitoring (FIM) integration.

**Elastic FIM Integration Setup**

To configure the Elastic FIM integration, follow these steps:

1. Install and configure the Elastic Agent on your Linux system. You can refer to the [Elastic Agent documentation](docs-content://reference/ingestion-tools/fleet/install-elastic-agents.md) for detailed instructions.
2. Once the Elastic Agent is installed, navigate to the Elastic Security app in Kibana.
3. In the Kibana home page, click on "Integrations" in the left sidebar.
4. Search for "File Integrity Monitoring" in the search bar and select the integration.
5. Provide a name and optional description for the integration.
6. Select the appropriate agent policy for your Linux system or create a new one.
7. Configure the FIM policy by specifying the paths that you want to monitor for file modifications. You can use the same paths mentioned in the `query` field of the rule. Note that FIM does not accept wildcards in the paths, so you need to specify the exact paths you want to monitor.
8. Save the configuration and the Elastic Agent will start monitoring the specified paths for file modifications.

For more details on configuring the Elastic FIM integration, you can refer to the [Elastic FIM documentation](https://docs.elastic.co/integrations/fim).


## Rule query [_rule_query_4812]

```js
file where host.os.type == "linux" and event.dataset == "fim.event" and event.action == "updated" and
file.path : (
  // cron, anacron & at
  "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.monthly/*",
  "/etc/cron.weekly/*", "/etc/crontab", "/var/spool/cron/crontabs/*", "/etc/cron.allow",
  "/etc/cron.deny",  "/var/spool/anacron/*", "/var/spool/cron/atjobs/*",

  // systemd services & timers
  "/etc/systemd/system/*", "/usr/local/lib/systemd/system/*", "/lib/systemd/system/*",
  "/usr/lib/systemd/system/*", "/home/*/.config/systemd/user/*", "/home/*/.local/share/systemd/user/*",
  "/root/.config/systemd/user/*", "/root/.local/share/systemd/user/*",

  // LD_PRELOAD
  "/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf",

  // Dynamic linker
  "/lib/ld-linux*.so*", "/lib64/ld-linux*.so*", "/usr/lib/ld-linux*.so*", "/usr/lib64/ld-linux*.so*",

  // message-of-the-day (MOTD)
  "/etc/update-motd.d/*",

  // SSH
  "/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*",

  // system-wide shell configurations
  "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/zsh/*", "/etc/csh.cshrc",
  "/etc/csh.login", "/etc/fish/config.fish", "/etc/ksh.kshrc",

  // root and user shell configurations
  "/home/*/.profile", "/home/*/.bashrc", "/home/*/.bash_login", "/home/*/.bash_logout",
  "/root/.profile", "/root/.bashrc", "/root/.bash_login", "/root/.bash_logout",
  "/home/*/.zprofile", "/home/*/.zshrc", "/root/.zprofile", "/root/.zshrc",
  "/home/*/.cshrc", "/home/*/.login", "/home/*/.logout", "/root/.cshrc", "/root/.login", "/root/.logout",
  "/home/*/.config/fish/config.fish", "/root/.config/fish/config.fish",
  "/home/*/.kshrc", "/root/.kshrc",

  // runtime control
  "/etc/rc.common", "/etc/rc.local",

  // System V init/Upstart
  "/etc/init.d/*", "/etc/init/*",

  // passwd/sudoers/shadow
  "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*",

  // Systemd udevd
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*", "/usr/local/lib/udev/rules.d/*",

  // XDG/KDE autostart entries
  "/home/*/.config/autostart/*", "/root/.config/autostart/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",
  "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
  "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
  "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
  "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
  "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*",

  // LKM configuration files
  "/etc/modules", "/etc/modprobe.d/*", "/usr/lib/modprobe.d/*", "/etc/modules-load.d/*",
  "/run/modules-load.d/*", "/usr/local/lib/modules-load.d/*", "/usr/lib/modules-load.d/*",

  // PAM modules & configuration files
  "/lib/security/*", "/lib64/security/*", "/usr/lib/security/*", "/usr/lib64/security/*",
  "/lib/x86_64-linux-gnu/security/*", "/usr/lib/x86_64-linux-gnu/security/*",
  "/etc/pam.d/*", "/etc/security/pam_*", "/etc/pam.conf",

  // Misc.
  "/etc/shells"

) and not (
  file.path : (
    "/var/spool/cron/crontabs/tmp.*", "/run/udev/rules.d/*rules.*", "/home/*/.ssh/known_hosts.*", "/root/.ssh/known_hosts.*"
  ) or
  file.extension in ("dpkg-new", "dpkg-remove", "SEQ")
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

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Local Account
    * ID: T1136.001
    * Reference URL: [https://attack.mitre.org/techniques/T1136/001/](https://attack.mitre.org/techniques/T1136/001/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



