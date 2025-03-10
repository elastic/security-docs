---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-process-for-a-windows-host.html
---

# Unusual Process For a Windows Host [prebuilt-rule-8-2-1-unusual-process-for-a-windows-host]

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
* Windows
* Threat Detection
* ML

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2261]

## Triage and analysis

##  Investigating an Unusual Windows Process

Searching for abnormal Windows processes is a good methodology to find potentially malicious activity within a network.
Understanding what is commonly run within an environment and developing baselines for legitimate activity can help
uncover potential malware and suspicious behaviors.

### Possible investigation steps:
- Consider the user as identified by the `user.name` field. Is this program part of an expected workflow for the user who ran this program on this host?
- Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process metadata like the values of the Company, Description and Product fields which may indicate whether the program is associated with an expected software vendor or package.
- Examine arguments and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing.
- Consider the same for the parent process. If the parent process is a legitimate system utility or service, this could be related to software updates or system management. If the parent process is something user-facing like an Office application, this process could be more suspicious.
- If you have file hash values in the event data, and you suspect malware, you can optionally run a search for the file hash to see if the file is identified as malware by anti-malware tools.

## False Positive Analysis
- Validate the unusual Windows process is not related to new benign software installation activity. If related to
legitimate software, this can be done by leveraging the exception workflow in the Kibana Security App or Elasticsearch
API to tune this rule to your environment.
- Try to understand the context of the execution by thinking about the user, machine, or business purpose.  It's possible that a small number of endpoints
such as servers that have very unique software that might appear to be unusual, but satisfy a specific business need.

## Related Rules
- Anomalous Windows Process Creation
- Unusual Windows Path Activity
- Unusual Windows Process Calling the Metadata Service

## Response and Remediation
- This rule is related to process execution events and should be immediately reviewed and investigated to determine if malicious.
- Based on validation and if malicious, the impacted machine should be isolated and analyzed to determine other post-compromise
behavior such as setting up persistence or performing lateral movement.
- Look into preventive measures such as Windows Defender Application Control and AppLocker to gain better control on
what is allowed to run on Windows infrastructure.

