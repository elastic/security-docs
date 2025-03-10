---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-system-binary-path-file-permission-modification.html
---

# System Binary Path File Permission Modification [prebuilt-rule-8-17-3-system-binary-path-file-permission-modification]

This rule identifies file permission modification events on files located in common system binary paths. Adversaries may attempt to hide their payloads in the default Linux system directories, and modify the file permissions of these payloads prior to execution.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/](https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_797]

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


## Rule query [_rule_query_4830]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name in ("chmod", "chown") and
process.args like~ (
  "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*",
  "/lib/*", "/usr/lib/*", "/lib64/*", "/usr/lib64/*"
) and
process.args in ("4755", "755", "000", "777", "444", "-x", "+x") and not (
  process.args in ("/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod") or
  process.parent.executable like~ ("/tmp/newroot/*", "/var/lib/dpkg/info/*") or
  process.parent.name in ("udevadm", "systemd", "entrypoint", "sudo", "dart") or
  process.parent.command_line == "runc init" or
  process.parent.args like "/var/tmp/rpm-tmp.*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



