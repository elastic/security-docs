---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-anomalous-process-for-a-linux-population.html
---

# Anomalous Process For a Linux Population [prebuilt-rule-8-1-1-anomalous-process-for-a-linux-population]

Searches for rare processes running on multiple Linux hosts in an entire fleet or network. This reduces the detection of false positives since automated maintenance processes usually only run occasionally on a single machine but are common to all or many hosts in a fleet.

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

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1698]

## Triage and analysis

## Investigating an Unusual Linux Process
Detection alerts from this rule indicate the presence of a Linux process that is rare and unusual for all of the monitored Linux hosts for which Auditbeat data is available. Here are some possible avenues of investigation:
- Consider the user as identified by the username field. Is this program part of an expected workflow for the user who ran this program on this host?
- Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing.

