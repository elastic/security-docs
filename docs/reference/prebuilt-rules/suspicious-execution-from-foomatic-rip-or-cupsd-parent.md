---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-execution-from-foomatic-rip-or-cupsd-parent.html
---

# Suspicious Execution from Foomatic-rip or Cupsd Parent [suspicious-execution-from-foomatic-rip-or-cupsd-parent]

This detection rule addresses multiple vulnerabilities in the CUPS printing system, including CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177. Specifically, this rule detects suspicious process command lines executed by child processes of foomatic-rip and cupsd. These flaws impact components like cups-browsed, libcupsfilters, libppd, and foomatic-rip, allowing remote unauthenticated attackers to manipulate IPP URLs or inject malicious data through crafted UDP packets or network spoofing. This can result in arbitrary command execution when a print job is initiated.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/cups-overflow](https://www.elastic.co/security-labs/cups-overflow)
* [https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/](https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/)
* [https://gist.github.com/stong/c8847ef27910ae344a7b5408d9840ee1](https://gist.github.com/stong/c8847ef27910ae344a7b5408d9840ee1)
* [https://github.com/RickdeJager/cupshax/blob/main/cupshax.py](https://github.com/RickdeJager/cupshax/blob/main/cupshax.py)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Use Case: Vulnerability
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_982]

**Triage and analysis**

**Investigating Suspicious Execution from Foomatic-rip or Cupsd Parent**

This rule identifies potential exploitation attempts of several vulnerabilities in the CUPS printing system (CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, CVE-2024-47177). These vulnerabilities allow attackers to send crafted IPP requests or manipulate UDP packets to execute arbitrary commands or modify printer configurations. Attackers can exploit these flaws to inject malicious data, leading to Remote Code Execution (RCE) on affected systems.

**Possible Investigation Steps**

* Investigate the incoming IPP requests or UDP packets targeting port 631.
* Examine the printer configurations on the system to determine if any unauthorized printers or URLs have been added.
* Investigate the process tree to check if any unexpected processes were triggered as a result of IPP activity. Review the executable files for legitimacy.
* Check for additional alerts related to the compromised system or user within the last 48 hours.
* Investigate network traffic logs for suspicious outbound connections to unrecognized domains or IP addresses.
* Check if any of the contacted domains or addresses are newly registered or have a suspicious reputation.
* Retrieve any scripts or executables dropped by the attack for further analysis in a private sandbox environment:
* Analyze potential malicious activity, including:
* Attempts to communicate with external servers.
* File access or creation of unauthorized executables.
* Cron jobs, services, or other persistence mechanisms.

**Related Rules**

* Cupsd or Foomatic-rip Shell Execution - 476267ff-e44f-476e-99c1-04c78cb3769d
* Printer User (lp) Shell Execution - f86cd31c-5c7e-4481-99d7-6875a3e31309
* Network Connection by Cups or Foomatic-rip Child - e80ee207-9505-49ab-8ca8-bc57d80e2cab
* File Creation by Cups or Foomatic-rip Child - b9b14be7-b7f4-4367-9934-81f07d2f63c4

**False Positive Analysis**

* This activity is rarely legitimate. However, verify the context to rule out non-malicious printer configuration changes or legitimate IPP requests.

**Response and Remediation**

* Initiate the incident response process based on the triage outcome.
* Isolate the compromised host to prevent further exploitation.
* If the investigation confirms malicious activity, search the environment for additional compromised hosts.
* Implement network segmentation or restrictions to contain the attack.
* Stop suspicious processes or services tied to CUPS exploitation.
* Block identified Indicators of Compromise (IoCs), including IP addresses, domains, or hashes of involved files.
* Review compromised systems for backdoors, such as reverse shells or persistence mechanisms like cron jobs.
* Investigate potential credential exposure on compromised systems and reset passwords for any affected accounts.
* Restore the original printer configurations or uninstall unauthorized printer entries.
* Perform a thorough antimalware scan to identify any lingering threats or artifacts from the attack.
* Investigate how the attacker gained initial access and address any weaknesses to prevent future exploitation.
* Use insights from the incident to improve detection and response times in future incidents (MTTD and MTTR).


## Setup [_setup_624]

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


## Rule query [_rule_query_1030]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name in ("foomatic-rip", "cupsd") and process.command_line like (
  // persistence
  "*cron*", "*/etc/rc.local*", "*/dev/tcp/*", "*/etc/init.d*", "*/etc/update-motd.d*", "*/etc/sudoers*",
  "*/etc/profile*", "*autostart*", "*/etc/ssh*", "*/home/*/.ssh/*", "*/root/.ssh*", "*~/.ssh/*", "*udev*",
  "*/etc/shadow*", "*/etc/passwd*",

  // Downloads
  "*curl*", "*wget*",

  // encoding and decoding
  "*base64 *", "*base32 *", "*xxd *", "*openssl*",

  // reverse connections
  "*GS_ARGS=*", "*/dev/tcp*", "*/dev/udp/*", "*import*pty*spawn*", "*import*subprocess*call*", "*TCPSocket.new*",
  "*TCPSocket.open*", "*io.popen*", "*os.execute*", "*fsockopen*", "*disown*", "*nohup*",

  // SO loads
  "*openssl*-engine*.so*", "*cdll.LoadLibrary*.so*", "*ruby*-e**Fiddle.dlopen*.so*", "*Fiddle.dlopen*.so*",
  "*cdll.LoadLibrary*.so*",

  // misc. suspicious command lines
   "*/etc/ld.so*", "*/dev/shm/*", "*/var/tmp*", "*echo*", "*>>*", "*|*"
) and not process.args like "gs*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Exploitation for Client Execution
    * ID: T1203
    * Reference URL: [https://attack.mitre.org/techniques/T1203/](https://attack.mitre.org/techniques/T1203/)



