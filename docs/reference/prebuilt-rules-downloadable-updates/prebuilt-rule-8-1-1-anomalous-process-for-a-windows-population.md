---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-anomalous-process-for-a-windows-population.html
---

# Anomalous Process For a Windows Population [prebuilt-rule-8-1-1-anomalous-process-for-a-windows-population]

Searches for rare processes running on multiple hosts in an entire fleet or network. This reduces the detection of false positives since automated maintenance processes usually only run occasionally on a single machine but are common to all or many hosts in a fleet.

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

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1703]

## Triage and analysis

## Investigating an Unusual Windows Process
Detection alerts from this rule indicate the presence of a Windows process that is rare and unusual for all of the Windows hosts for which Winlogbeat data is available. Here are some possible avenues of investigation:
- Consider the user as identified by the username field. Is this program part of an expected workflow for the user who ran this program on this host?
- Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process metadata like the values of the Company, Description and Product fields which may indicate whether the program is associated with an expected software vendor or package.
- Examine arguments and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing.
- Consider the same for the parent process. If the parent process is a legitimate system utility or service, this could be related to software updates or system management. If the parent process is something user-facing like an Office application, this process could be more suspicious.
- If you have file hash values in the event data, and you suspect malware, you can optionally run a search for the file hash to see if the file is identified as malware by anti-malware tools.

