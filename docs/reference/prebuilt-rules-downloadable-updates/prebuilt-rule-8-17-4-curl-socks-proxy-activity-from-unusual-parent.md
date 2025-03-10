---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-curl-socks-proxy-activity-from-unusual-parent.html
---

# Curl SOCKS Proxy Activity from Unusual Parent [prebuilt-rule-8-17-4-curl-socks-proxy-activity-from-unusual-parent]

This rule detects the use of the `curl` command-line tool with SOCKS proxy options, launched from an unusual parent process. Attackers may use `curl` to establish a SOCKS proxy connection to bypass network restrictions and exfiltrate data or communicate with C2 servers.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4303]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Curl SOCKS Proxy Activity from Unusual Parent**

Curl is a versatile command-line tool used for transferring data with URLs, often employed for legitimate data retrieval. However, adversaries can exploit its SOCKS proxy capabilities to bypass network restrictions, facilitating covert data exfiltration or communication with command and control servers. The detection rule identifies suspicious curl executions initiated by atypical parent processes, such as those from temporary directories or shell environments, combined with SOCKS proxy arguments, indicating potential misuse.

**Possible investigation steps**

* Review the parent process details to understand the context of the curl execution, focusing on unusual directories like /dev/shm, /tmp, or shell environments such as bash or zsh.
* Examine the command-line arguments used with curl, specifically looking for SOCKS proxy options like --socks5-hostname or -x, to determine the intent and destination of the network request.
* Investigate the environment variables set for the process, such as http_proxy or HTTPS_PROXY, to identify any proxy configurations that might indicate an attempt to bypass network restrictions.
* Check the user account associated with the process execution to determine if it aligns with expected behavior or if it might be compromised.
* Analyze network logs to trace the destination IP addresses or domains contacted via the SOCKS proxy to assess if they are known malicious or suspicious entities.
* Correlate this activity with other alerts or logs from the same host to identify any patterns or additional indicators of compromise.

**False positive analysis**

* Development environments may frequently use curl with SOCKS proxy options for legitimate testing purposes. To manage this, consider excluding specific development directories or user accounts from the rule.
* Automated scripts or cron jobs running from shell environments might use curl with SOCKS proxies for routine data retrieval. Identify these scripts and exclude their parent processes or specific arguments from triggering the rule.
* System administrators might use curl with SOCKS proxies for network diagnostics or maintenance tasks. Document these activities and create exceptions for known administrative accounts or specific command patterns.
* Web applications hosted in directories like /var/www/html may use curl for backend operations involving SOCKS proxies. Review these applications and whitelist their specific processes or arguments if they are verified as non-threatening.
* Temporary directories such as /tmp or /dev/shm might be used by legitimate software for transient operations involving curl. Monitor these occurrences and exclude known benign software from the rule.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further data exfiltration or communication with command and control servers.
* Terminate any suspicious curl processes identified by the detection rule to halt potential malicious activity.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized file modifications or additional malicious processes.
* Review and clean up any unauthorized or suspicious files in temporary directories or other unusual locations, such as /dev/shm, /tmp, or /var/tmp, to remove potential threats.
* Reset credentials and review access logs for any accounts that may have been compromised or used in conjunction with the detected activity.
* Implement network monitoring to detect and block any further attempts to use SOCKS proxy connections from unauthorized sources.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if broader organizational impacts exist.


## Setup [_setup_1158]

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

Elastic Defend integration does not collect environment variable logging by default. In order to capture this behavior, this rule requires a specific configuration option set within the advanced settings of the Elastic Defend integration. ## To set up environment variable capture for an Elastic Agent policy: - Go to “Security → Manage → Policies”. - Select an “Elastic Agent policy”. - Click “Show advanced settings”. - Scroll down or search for “linux.advanced.capture_env_vars”. - Enter the names of environment variables you want to capture, separated by commas. - For this rule the linux.advanced.capture_env_vars variable should be set to "HTTP_PROXY,HTTPS_PROXY,ALL_PROXY". - Click “Save”. After saving the integration change, the Elastic Agents running this policy will be updated and the rule will function properly. For more information on capturing environment variables refer to the [helper guide](docs-content://solutions/security/cloud/capture-environment-variables.md).


## Rule query [_rule_query_5295]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "curl" and (
  process.parent.executable like (
    "/dev/shm/*", "/tmp/*", "/var/tmp/*", "/var/run/*", "/root/*", "/boot/*", "/var/www/html/*", "/opt/.*"
  ) or
  process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
) and (
  process.args like ("--socks5-hostname", "--proxy", "--preproxy", "socks5*") or
  process.args == "-x" or
  process.env_vars like ("http_proxy=socks5h://*", "HTTPS_PROXY=socks5h://*", "ALL_PROXY=socks5h://*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



