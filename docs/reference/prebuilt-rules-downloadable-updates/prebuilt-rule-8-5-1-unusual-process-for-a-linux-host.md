---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-unusual-process-for-a-linux-host.html
---

# Unusual Process For a Linux Host [prebuilt-rule-8-5-1-unusual-process-for-a-linux-host]

Identifies rare processes that do not usually run on individual hosts, which can indicate execution of unauthorized services, malware, or persistence mechanisms. Processes are considered rare when they only run occasionally as compared with other processes running on the host.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* ML
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3679]

## Triage and analysis

##  Investigating Unusual Process For a Linux Host

Searching for abnormal Linux processes is a good methodology to find potentially malicious activity within a network. Understanding what is commonly run within an environment and developing baselines for legitimate activity can help uncover potential malware and suspicious behaviors.

This rule uses a machine learning job to detect a Linux process that is rare and unusual for an individual Linux host in your environment.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, and whether they are located in expected locations.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Consider the user as identified by the `user.name` field. Is this program part of an expected workflow for the user who ran this program on this host?
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
- Validate if the activity has a consistent cadence (for example, if it runs monthly or quarterly), as it could be part of a monthly or quarterly business process.
- Examine the arguments and working directory of the process. These may provide indications as to the source of the program or the nature of the tasks it is performing.

## False Positive Analysis

- If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
- Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

## Response and Remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)



