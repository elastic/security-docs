---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-linux-ransomware-note-creation-detected.html
---

# Potential Linux Ransomware Note Creation Detected [prebuilt-rule-8-17-4-potential-linux-ransomware-note-creation-detected]

This rule identifies a sequence of a mass file encryption event in conjunction with the creation of a .txt file with a file name containing ransomware keywords executed by the same process in a 1 second timespan. Ransomware is a type of malware that encrypts a victim’s files or systems and demands payment (usually in cryptocurrency) in exchange for the decryption key. One important indicator of a ransomware attack is the mass encryption of the file system, after which a new file extension is added to the file.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Impact
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4431]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Linux Ransomware Note Creation Detected**

Ransomware encrypts files, demanding payment for decryption. Adversaries exploit Linux systems by executing mass file renaming and creating ransom notes. This detection rule identifies such behavior by monitoring rapid file changes and the creation of text files with ransom-related keywords, indicating potential ransomware activity. It focuses on unusual file operations in critical directories, excluding benign processes, to flag suspicious activities.

**Possible investigation steps**

* Review the process.entity_id and host.id to identify the specific process and host involved in the alert. This will help in understanding the scope and potential impact of the activity.
* Examine the process.executable path to determine if the executable is located in a suspicious directory such as /tmp, /var/tmp, or /dev/shm, which are commonly used by adversaries for malicious activities.
* Analyze the file paths involved in the rename events to assess if critical directories like /home/*/Documents, /root, or /var/www are affected, indicating a higher risk of data compromise.
* Check the process.name against the list of excluded benign processes to ensure the activity is not a false positive caused by legitimate software updates or installations.
* Investigate the content and metadata of the created .txt files with names containing keywords like **restore**, **lock**, or **ransom** to confirm if they contain ransom notes or instructions, which would indicate a ransomware attack.
* Correlate the timing of the file rename and creation events to verify if they occurred within the 1-second timespan, supporting the hypothesis of a rapid mass encryption event typical of ransomware behavior.
* Assess the risk score and severity level to prioritize the response and determine if immediate containment actions are necessary to prevent further damage.

**False positive analysis**

* Frequent software updates or installations can trigger the rule due to mass file renaming in critical directories. Exclude processes like dpkg, yum, dnf, and rpm if they are part of regular system maintenance.
* Development activities involving compilers or interpreters such as go, java, python, and node may cause false positives. Consider excluding these processes if they are part of routine development work.
* Automated backup or logging processes might create files with names similar to ransom notes. Exclude directories or processes associated with legitimate backup or logging activities to reduce false alerts.
* System administration tasks using tools like ansible-galaxy or semodule can mimic ransomware behavior. Exclude these processes if they are part of scheduled or known administrative operations.
* Web server operations in directories like /var/www/* might involve file creation and renaming. Exclude specific web server processes if they are identified as non-threatening and part of regular operations.

**Response and remediation**

* Isolate the affected Linux system from the network immediately to prevent further spread of the ransomware and protect other systems.
* Identify and terminate the malicious process responsible for the mass file renaming and ransom note creation using the process.entity_id and host.id from the alert.
* Backup any unencrypted files and critical data from the affected system to a secure location to prevent data loss.
* Conduct a forensic analysis of the affected system to determine the entry point and scope of the ransomware attack, focusing on the directories and processes identified in the alert.
* Restore the affected system from a known good backup prior to the ransomware attack to ensure system integrity and data recovery.
* Apply security patches and updates to the affected system and any other vulnerable systems to close any exploited vulnerabilities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to enhance detection capabilities for similar threats in the future.


## Setup [_setup_1274]

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


## Rule query [_rule_query_5423]

```js
sequence by process.entity_id, host.id with maxspan=1s
  [file where host.os.type == "linux" and event.type == "change" and event.action == "rename" and file.extension : "?*"
   and process.executable : ("./*", "/tmp/*", "/var/tmp/*", "/dev/shm/*", "/var/run/*", "/boot/*") and
   file.path : (
     "/home/*/Downloads/*", "/home/*/Documents/*", "/root/*", "/bin/*", "/usr/bin/*", "/var/log/*", "/var/lib/log/*",
     "/var/backup/*", "/var/www/*") and
   not process.name : (
     "dpkg", "yum", "dnf", "rpm", "dockerd", "go", "java", "pip*", "python*", "node", "containerd", "php", "p4d",
     "conda", "chrome", "imap", "cmake", "firefox", "semanage", "semodule", "ansible-galaxy", "fc-cache", "jammy", "git",
     "systemsettings", "vmis-launcher", "bundle", "kudu-tserver", "suldownloader", "rustup-init", "bun"
    )
  ] with runs=25
  [file where host.os.type == "linux" and event.action == "creation" and
   file.name : ("*restore*", "*lock*", "*recovery*", "*read*", "*instruction*", "*how_to*", "*ransom*")
  ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



