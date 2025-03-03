---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-execution-of-rc-local-script.html
---

# Potential Execution of rc.local Script [prebuilt-rule-8-17-4-potential-execution-of-rc-local-script]

This rule detects the potential execution of the `/etc/rc.local` script through the `already_running` event action created by the `rc-local.service` systemd service. The `/etc/rc.local` script is a legacy initialization script that is executed at the end of the boot process. The `/etc/rc.local` script is not enabled by default on most Linux distributions. The `/etc/rc.local` script can be used by attackers to persistently execute malicious commands or scripts on a compromised system at reboot. As the rc.local file is executed prior to the initialization of Elastic Defend, the execution event is not ingested, and therefore the `already_running` event is leveraged to provide insight into the potential execution of `rc.local`.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*

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
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4483]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Execution of rc.local Script**

The `/etc/rc.local` script is a legacy Linux initialization script executed at the end of the boot process. While not enabled by default, attackers can exploit it to persistently run malicious commands upon system reboot. The detection rule identifies potential misuse by monitoring for the `already_running` event action linked to `rc-local.service`, indicating the script’s execution, thus alerting to possible persistence tactics.

**Possible investigation steps**

* Review the system logs to identify any recent changes or modifications to the /etc/rc.local file, focusing on timestamps and user accounts involved in the changes.
* Examine the contents of the /etc/rc.local file to identify any suspicious or unauthorized commands or scripts that may have been added.
* Investigate the process tree and parent processes associated with the rc-local.service to determine if there are any unusual or unexpected parent processes that could indicate compromise.
* Check for any other persistence mechanisms or indicators of compromise on the system, such as unauthorized user accounts or scheduled tasks, to assess the broader impact of the potential threat.
* Correlate the event with other security alerts or logs from the same host to identify any patterns or related activities that could provide additional context or evidence of malicious behavior.

**False positive analysis**

* System maintenance scripts: Some Linux distributions or administrators may use the rc.local script for legitimate system maintenance tasks. Review the script’s content to verify its purpose and consider excluding these known benign scripts from triggering alerts.
* Custom startup configurations: Organizations might have custom startup configurations that utilize rc.local for non-malicious purposes. Document these configurations and create exceptions in the detection rule to prevent unnecessary alerts.
* Legacy applications: Certain legacy applications might rely on rc.local for initialization. Identify these applications and assess their necessity. If deemed safe, exclude their execution from the rule to reduce false positives.
* Testing environments: In testing or development environments, rc.local might be used for various non-threatening experiments. Clearly label these environments and adjust the rule to ignore alerts originating from them.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious scripts and limit the attacker’s access.
* Review the contents of the `/etc/rc.local` file on the affected system to identify any unauthorized or suspicious commands or scripts. Remove any malicious entries found.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malware or persistence mechanisms.
* Restore the system from a known good backup if the integrity of the system is in question and if malicious activity is confirmed.
* Implement monitoring for changes to the `/etc/rc.local` file and other critical system files to detect unauthorized modifications in the future.
* Escalate the incident to the security operations team for further investigation and to determine if other systems may be affected.
* Review and update security policies and configurations to disable the execution of the `/etc/rc.local` script by default on all systems, unless explicitly required for legitimate purposes.


## Setup [_setup_1321]

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


## Rule query [_rule_query_5475]

```js
process where host.os.type == "linux" and event.type == "info" and event.action == "already_running" and
process.parent.args == "/etc/rc.local" and process.parent.args == "start"
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



