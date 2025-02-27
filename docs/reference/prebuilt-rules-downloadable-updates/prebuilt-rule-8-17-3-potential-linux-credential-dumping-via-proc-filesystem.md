---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-linux-credential-dumping-via-proc-filesystem.html
---

# Potential Linux Credential Dumping via Proc Filesystem [prebuilt-rule-8-17-3-potential-linux-credential-dumping-via-proc-filesystem]

Identifies the execution of the mimipenguin exploit script which is linux adaptation of Windows tool mimikatz. Mimipenguin exploit script is used to dump clear text passwords from a currently logged-in user. The tool exploits a known vulnerability CVE-2018-20781. Malicious actors can exploit the cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin)
* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20781](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20781)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_820]

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


## Rule query [_rule_query_4861]

```js
sequence by host.id, process.parent.name with maxspan=1m
  [process where host.os.type == "linux" and process.name == "ps" and event.action in ("exec", "start", "exec_event")
   and process.args in ("-eo", "pid", "command")]
  [process where host.os.type == "linux" and process.name == "strings" and event.action in ("exec", "start", "exec_event")
   and process.args : "/tmp/*"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Proc Filesystem
    * ID: T1003.007
    * Reference URL: [https://attack.mitre.org/techniques/T1003/007/](https://attack.mitre.org/techniques/T1003/007/)

* Technique:

    * Name: Exploitation for Credential Access
    * ID: T1212
    * Reference URL: [https://attack.mitre.org/techniques/T1212/](https://attack.mitre.org/techniques/T1212/)



