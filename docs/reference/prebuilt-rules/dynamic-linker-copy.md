---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/dynamic-linker-copy.html
---

# Dynamic Linker Copy [dynamic-linker-copy]

Detects the copying of the Linux dynamic loader binary and subsequent file creation for the purpose of creating a backup copy. This technique was seen recently being utilized by Linux malware prior to patching the dynamic loader in order to inject and preload a malicious shared object file. This activity should never occur and if it does then it should be considered highly suspicious or malicious.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/](https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Threat: Orbit
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_281]

**Triage and analysis**

**Investigating Dynamic Linker Copy**

The Linux dynamic linker is responsible for loading shared libraries required by executables at runtime. It is a critical component of the Linux operating system and should not be tampered with.

Adversaries may attempt to copy the dynamic linker binary and create a backup copy before patching it to inject and preload malicious shared object files. This technique has been observed in recent Linux malware attacks and is considered highly suspicious or malicious.

The detection rule *Dynamic Linker Copy* is designed to identify such abuse by monitoring for processes with names "cp" or "rsync" that involve copying the dynamic linker binary ("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2") and modifying the "/etc/ld.so.preload" file. Additionally, the rule checks for the creation of new files with the "so" extension on Linux systems. By detecting these activities within a short time span (1 minute), the rule aims to alert security analysts to potential malicious behavior.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the dynamic linker that was copied or altered.
* !{osquery{"label":"Osquery - Retrieve File Listing Information","query":"SELECT * FROM file WHERE ( path = */etc/ld.so.preload* OR path = */lib64/ld-linux-x86-64.so.2* OR path =\n'/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2' OR path = */usr/lib64/ld-linux-x86-64.so.2* OR path =\n'/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2' )\n"}}
* !{osquery{"label":"Osquery - Retrieve Additional File Listing Information","query":"SELECT f.path, u.username AS file_owner, g.groupname AS group_owner, datetime(f.atime, *unixepoch*) AS\nfile_last_access_time, datetime(f.mtime, *unixepoch*) AS file_last_modified_time, datetime(f.ctime, *unixepoch*) AS\nfile_last_status_change_time, datetime(f.btime, *unixepoch*) AS file_created_time, f.size AS size_bytes FROM file f LEFT\nJOIN users u ON f.uid = u.uid LEFT JOIN groups g ON f.gid = g.gid WHERE ( path = */etc/ld.so.preload* OR path =\n'/lib64/ld-linux-x86-64.so.2' OR path = */lib/x86_64-linux-gnu/ld-linux-x86-64.so.2* OR path =\n'/usr/lib64/ld-linux-x86-64.so.2' OR path = */usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2* )\n"}}
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
* Investigate abnormal behaviors by the subject process/user such as network connections, file modifications, and any other spawned child processes.
* Investigate listening ports and open sockets to look for potential command and control traffic or data exfiltration.
* !{osquery{"label":"Osquery - Retrieve Listening Ports","query":"SELECT pid, address, port, socket, protocol, path FROM listening_ports"}}
* !{osquery{"label":"Osquery - Retrieve Open Sockets","query":"SELECT pid, family, remote_address, remote_port, socket, state FROM process_open_sockets"}}
* Identify the user account that performed the action, analyze it, and check whether it should perform this kind of action.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific User","query":"SELECT * FROM users WHERE username = {user.name}"}}`
* Investigate whether the user is currently logged in and active.
* `!{osquery{"label":"Osquery - Investigate the Account Authentication Status","query":"SELECT * FROM logged_in_users WHERE user = {user.name}"}}`

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.
* Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.
* The security team should address any potential benign true positive (B-TP), as this configuration can put the user and the domain at risk.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Related Rules**

* Modification of Dynamic Linker Preload Shared Object Inside A Container - 342f834b-21a6-41bf-878c-87d116eba3ee
* Modification of Dynamic Linker Preload Shared Object - 717f82c2-7741-4f9b-85b8-d06aeb853f4f
* Shared Object Created or Changed by Previously Unknown Process - aebaa51f-2a91-4f6a-850b-b601db2293f4

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_181]

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


## Rule query [_rule_query_293]

```js
sequence by process.entity_id with maxspan=1m
[process where host.os.type == "linux" and event.type == "start" and process.name in ("cp", "rsync") and
   process.args in (
     "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
     "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
    )]
[file where host.os.type == "linux" and event.action == "creation" and file.extension == "so"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



