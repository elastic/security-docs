---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-file-transfer-or-listener-established-via-netcat.html
---

# File Transfer or Listener Established via Netcat [prebuilt-rule-8-17-4-file-transfer-or-listener-established-via-netcat]

A netcat process is engaging in network activity on a Linux host. Netcat is often used as a persistence mechanism by exporting a reverse shell or by serving a shell on a listening port. Netcat is also sometimes used for data exfiltration.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
* [https://en.wikipedia.org/wiki/Netcat](https://en.wikipedia.org/wiki/Netcat)
* [https://www.hackers-arise.com/hacking-fundamentals](https://www.hackers-arise.com/hacking-fundamentals)
* [https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-netcat-swiss-army-knife-hacking-tools-0148657/](https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-netcat-swiss-army-knife-hacking-tools-0148657/)
* [https://levelup.gitconnected.com/ethical-hacking-part-15-netcat-nc-and-netcat-f6a8f7df43fd](https://levelup.gitconnected.com/ethical-hacking-part-15-netcat-nc-and-netcat-f6a8f7df43fd)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4395]

**Triage and analysis**

**Investigating File Transfer or Listener Established via Netcat**

Netcat is a dual-use command line tool that can be used for various purposes, such as port scanning, file transfers, and connection tests. Attackers can abuse its functionality for malicious purposes such creating bind shells or reverse shells to gain access to the target system.

A reverse shell is a mechanism that’s abused to connect back to an attacker-controlled system. It effectively redirects the system’s input and output and delivers a fully functional remote shell to the attacker. Even private systems are vulnerable since the connection is outgoing.

A bind shell is a type of backdoor that attackers set up on the target host and binds to a specific port to listen for an incoming connection from the attacker.

This rule identifies potential reverse shell or bind shell activity using Netcat by checking for the execution of Netcat followed by a network connection.

**Possible investigation steps**

* Examine the command line to identify if the command is suspicious.
* Extract and examine the target domain or IP address.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* Scope other potentially compromised hosts in your environment by mapping hosts that also communicated with the domain or IP address.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.
* Investigate any abnormal behavior by the subject process such as network connections, file modifications, and any spawned child processes.

**False positive analysis**

* Netcat is a dual-use tool that can be used for benign or malicious activity. It is included in some Linux distributions, so its presence is not necessarily suspicious. Some normal use of this program, while uncommon, may originate from scripts, automation tools, and frameworks.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Block the identified indicators of compromise (IoCs).
* Take actions to terminate processes and connections used by the attacker.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1239]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_5387]

```js
sequence by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and
      process.name:("nc","ncat","netcat","netcat.openbsd","netcat.traditional") and (
          /* bind shell to echo for command execution */
          (process.args:("-l","-p") and process.args:("-c","echo","$*"))
          /* bind shell to specific port */
          or process.args:("-l","-p","-lp")
          /* reverse shell to command-line interpreter used for command execution */
          or (process.args:("-e") and process.args:("/bin/bash","/bin/sh"))
          /* file transfer via stdout */
          or process.args:(">","<")
          /* file transfer via pipe */
          or (process.args:("|") and process.args:("nc","ncat"))
      ) and
      not process.command_line like~ ("*127.0.0.1*", "*localhost*")]
  [network where host.os.type == "linux" and (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional")]
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

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



