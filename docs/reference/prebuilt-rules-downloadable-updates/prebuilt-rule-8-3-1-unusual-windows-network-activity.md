---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-unusual-windows-network-activity.html
---

# Unusual Windows Network Activity [prebuilt-rule-8-3-1-unusual-windows-network-activity]

Identifies Windows processes that do not usually use the network but have unexpected network activity, which can indicate command-and-control, lateral movement, persistence, or data exfiltration activity. A process with unusual network activity can denote process exploitation or injection, where the process is used to run persistence mechanisms that allow a malicious actor remote access or control of the host, data exfiltration, and execution of unauthorized network applications.

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

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2297]

## Triage and analysis

## Investigating Unusual Network Activity
Detection alerts from this rule indicate the presence of network activity from a Windows process for which network activity is very unusual.  Here are some possible avenues of investigation:
- Consider the IP addresses, protocol and ports. Are these used by normal but infrequent network workflows? Are they expected or unexpected?
- If the destination IP address is remote or external, does it associate with an expected domain, organization or geography? Note: avoid interacting directly with suspected malicious IP addresses.
- Consider the user as identified by the username field. Is this network activity part of an expected workflow for the user who ran the program?
- Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing.
- Consider the same for the parent process. If the parent process is a legitimate system utility or service, this could be related to software updates or system management. If the parent process is something user-facing like an Office application, this process could be more suspicious.
- If you have file hash values in the event data, and you suspect malware, you can optionally run a search for the file hash to see if the file is identified as malware by anti-malware tools.

