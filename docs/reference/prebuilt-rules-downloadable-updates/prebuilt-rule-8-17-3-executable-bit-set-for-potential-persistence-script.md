---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-executable-bit-set-for-potential-persistence-script.html
---

# Executable Bit Set for Potential Persistence Script [prebuilt-rule-8-17-3-executable-bit-set-for-potential-persistence-script]

This rule monitors for the addition of an executable bit for scripts that are located in directories which are commonly abused for persistence. An alert of this rule is an indicator that a persistence mechanism is being set up within your environment. Adversaries may create these scripts to execute malicious code at start-up, or at a set interval to gain persistence onto the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
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
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_893]

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


## Rule query [_rule_query_4941]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.args : (
  // Misc.
  "/etc/rc.local", "/etc/rc.common", "/etc/rc.d/rc.local", "/etc/init.d/*", "/etc/update-motd.d/*",
  "/etc/apt/apt.conf.d/*", "/etc/cron*", "/etc/init/*", "/etc/NetworkManager/dispatcher.d/*",
  "/lib/dracut/modules.d/*", "/usr/lib/dracut/modules.d/*",

  // XDG
  "/etc/xdg/autostart/*", "/home/*/.config/autostart/*", "/root/.config/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*", "/home/*/.config/autostart-scripts/*",
  "/root/.config/autostart-scripts/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",

  // udev
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*"

) and (
  (process.name == "chmod" and process.args : ("+x*", "1*", "3*", "5*", "7*")) or
  (process.name == "install" and process.args : "-m*" and process.args : ("7*", "5*", "3*", "1*"))
) and not process.parent.executable : "/var/lib/dpkg/*"
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

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: XDG Autostart Entries
    * ID: T1547.013
    * Reference URL: [https://attack.mitre.org/techniques/T1547/013/](https://attack.mitre.org/techniques/T1547/013/)



