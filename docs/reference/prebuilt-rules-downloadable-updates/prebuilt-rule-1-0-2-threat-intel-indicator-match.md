---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-threat-intel-indicator-match.html
---

# Threat Intel Indicator Match [prebuilt-rule-1-0-2-threat-intel-indicator-match]

This rule is triggered when indicators from the Threat Intel integrations have a match against local file or network observations.

**Rule type**: threat_match

**Rule indices**:

* auditbeat-*
* endgame-*
* filebeat-*
* logs-*
* packetbeat-*
* winlogbeat-*

**Severity**: critical

**Risk score**: 99

**Runs every**: 1h

**Searches indices from**: now-65m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-threatintel.md](beats://reference/filebeat/filebeat-module-threatintel.md)

**Tags**:

* Elastic
* Windows
* Elastic Endgame
* Network
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1386]

## Triage and Analysis

## Investigating Threat Intel Indicator Matches

Threat Intel indicator match rules allow matching from a local observation such as an endpoint event that records a file
hash with an entry of a file hash stored within the Threat Intel integrations. Matches can also occur on
an IP address, registry path, URL, or imphash.

The matches will be based on the incoming last 30 days feed data so it's important to validate the data and review the results by
investigating the associated activity to determine if it requires further investigation.

If an indicator matches a local observation, the following enriched fields will be generated to identify the indicator, field, and type matched.

- `threat.indicator.matched.atomic` - this identifies the atomic indicator that matched the local observation
- `threat.indicator.matched.field` - this identifies the indicator field that matched the local observation
- `threat.indicator.matched.type` - this identifies the indicator type that matched the local observation

### Possible investigation steps:
- Investigation should be validated and reviewed based on the data (file hash, registry path, URL, imphash) that was matched
and by viewing the source of that activity.
- Consider the history of the indicator that was matched. Has it happened before? Is it happening on multiple machines?
These kinds of questions can help understand if the activity is related to legitimate behavior.
- Consider the user and their role within the company: is this something related to their job or work function?

## False Positive Analysis
- For any matches found, it's important to consider the initial release date of that indicator. Threat intelligence can
be a great tool for augmenting existing security processes, while at the same time it should be understood that threat
intelligence can represent a specific set of activity observed at a point in time. For example, an IP address
may have hosted malware observed in a Dridex campaign months ago, but it's possible that IP has been remediated and
no longer represents any threat.
- Adversaries often use legitimate tools as network administrators such as `PsExec` or `AdFind`; these tools often find their
way into indicator lists creating the potential for false positives.
- It's possible after large and publicly written campaigns, curious employees might end up going directly to attacker infrastructure and triggering these rules.

## Response and Remediation
- If suspicious or malicious behavior is observed, take immediate action to isolate activity to prevent further
post-compromise behavior.
- One example of a response if a machine matched a command and control IP address would be to add an entry to a network
device such as a firewall or proxy appliance to prevent any outbound activity from leaving that machine.
- Another example of a response with a malicious file hash match would involve validating if the file was properly quarantined,
reviewing current running processes for any abnormal activity, and investigating for any other follow-up actions such as persistence or lateral movement.

## Rule query [_rule_query_1619]

```js
file.hash.*:* or file.pe.imphash:* or source.ip:* or destination.ip:* or url.full:* or registry.path:*
```


