---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/abnormal-process-id-or-lock-file-created.html
---

# Abnormal Process ID or Lock File Created [abnormal-process-id-or-lock-file-created]

Identifies the creation of a Process ID (PID), lock or reboot file created in temporary file storage paradigm (tmpfs) directory /var/run. On Linux, the PID files typically hold the process ID to track previous copies running and manage other tasks. Certain Linux malware use the /var/run directory for holding data, executables and other tasks, disguising itself or these files as legitimate PID files.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/](https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://exatrack.com/public/Tricephalic_Hellkeeper.pdf](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf)
* [https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor](https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Threat: BPFDoor
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 215

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_110]

**Triage and analysis**

**Investigating Abnormal Process ID or Lock File Created**

Linux applications may need to save their process identification number (PID) for various purposes: from signaling that a program is running to serving as a signal that a previous instance of an application didn’t exit successfully. PID files contain its creator process PID in an integer value.

Linux lock files are used to coordinate operations in files so that conflicts and race conditions are prevented.

This rule identifies the creation of PID, lock, or reboot files in the /var/run/ directory. Attackers can masquerade malware, payloads, staged data for exfiltration, and more as legitimate PID files.

**Possible investigation steps**

* Retrieve the file and determine if it is malicious:
* Check the contents of the PID files. They should only contain integer strings.
* Check the file type of the lock and PID files to determine if they are executables. This is only observed in     malicious files.
* Check the size of the subject file. Legitimate PID files should be under 10 bytes.
* Check if the lock or PID file has high entropy. This typically indicates an encrypted payload.
* Analysts can use tools like `ent` to measure entropy.
* Examine the reputation of the SHA-256 hash in the PID file. Use a database like VirusTotal to identify additional pivots and artifacts for investigation.
* Trace the file’s creation to ensure it came from a legitimate or authorized process.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.
* Investigate any abnormal behavior by the subject process such as network connections, file modifications, and any spawned child processes.

**False positive analysis**

* False positives can appear if the PID file is legitimate and holding a process ID as intended. If the PID file is an executable or has a file size that’s larger than 10 bytes, it should be ruled suspicious.
* If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of file name and process executable conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Block the identified indicators of compromise (IoCs).
* Take actions to terminate processes and connections used by the attacker.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_62]

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


## Rule query [_rule_query_114]

```js
host.os.type:linux and event.category:file and event.action:(creation or file_create_event) and
file.extension:(pid or lock or reboot) and file.path:(/var/run/* or /run/*) and (
  (process.name : (
    bash or dash or sh or tcsh or csh or zsh or ksh or fish or ash or touch or nano or vim or vi or editor or mv or cp)
  ) or (
  process.executable : (
    ./* or /tmp/* or /var/tmp/* or /dev/shm/* or /var/run/* or /boot/* or /srv/* or /run/*
  ))
) and not (
  process.executable : (
  /tmp/newroot/* or /run/containerd/* or /run/k3s/containerd/* or /run/k0s/container* or /snap/* or /vz/* or
  /var/lib/docker/* or /etc/*/universal-hooks/pkgs/mysql-community-server/* or /var/lib/snapd/* or /etc/rubrik/* or
  /run/udev/data/*
  ) or
  process.name : (
    go or git or containerd* or snap-confine or cron or crond or sshd or unattended-upgrade or vzctl or ifup or
    rpcbind or runc or gitlab-runner-helper or elastic-agent or metricbeat or redis-server or libvirt_leaseshelper or
    s6-ipcserver-socketbinder or xinetd or libvirtd or veeamdeploymentsvc  or dnsmasq or virtlogd or lynis or
    veeamtransport
  ) or
  file.name : (
    jem.*.pid or lynis.pid or redis.pid or yum.pid or MFS.pid or jenkins.pid or nvmupdate.pid or openlitespeed.pid or
    rhnsd.pid
  ) or
  file.path : (/run/containerd/* or /var/run/docker/containerd/* or /var/run/jem*.pid)
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



