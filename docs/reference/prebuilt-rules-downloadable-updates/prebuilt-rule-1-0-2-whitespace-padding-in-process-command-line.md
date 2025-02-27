---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-whitespace-padding-in-process-command-line.html
---

# Whitespace Padding in Process Command Line [prebuilt-rule-1-0-2-whitespace-padding-in-process-command-line]

Identifies process execution events where the command line value contains a long sequence of whitespace characters or multiple occurrences of contiguous whitespace. Attackers may attempt to evade signature-based detections by padding their malicious command with unnecessary whitespace characters. These observations should be investigated for malicious behavior.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/JohnLaTwC/status/1419251082736201737](https://twitter.com/JohnLaTwC/status/1419251082736201737)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1572]

## Triage and analysis

- Analyze the command line of the process in question for evidence of malicious code execution.
- Review the ancestor and child processes spawned by the process in question for indicators of further malicious code execution.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1818]

```js
process where event.type in ("start", "process_started") and
  process.command_line regex ".*[ ]{20,}.*" or

  /* this will match on 3 or more separate occurrences of 5+ contiguous whitespace characters */
  process.command_line regex ".*(.*[ ]{5,}[^ ]*){3,}.*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



