---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-linux-network-activity.html
---

# Unusual Linux Network Activity [prebuilt-rule-8-1-1-unusual-linux-network-activity]

Identifies Linux processes that do not usually use the network but have unexpected network activity, which can indicate command-and-control, lateral movement, persistence, or data exfiltration activity. A process with unusual network activity can denote process exploitation or injection, where the process is used to run persistence mechanisms that allow a malicious actor remote access or control of the host, data exfiltration, and execution of unauthorized network applications.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* ML

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1697]

## Triage and analysis

## Investigating Unusual Network Activity
Detection alerts from this rule indicate the presence of network activity from a Linux process for which network activity is rare and unusual.  Here are some possible avenues of investigation:
- Consider the IP addresses and ports. Are these used by normal but infrequent network workflows? Are they expected or unexpected?
- If the destination IP address is remote or external, does it associate with an expected domain, organization or geography? Note: avoid interacting directly with suspected malicious IP addresses.
- Consider the user as identified by the username field. Is this network activity part of an expected workflow for the user who ran the program?
- Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business or maintenance process.
- Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing.

