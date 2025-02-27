---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-process-execution-temp.html
---

# Unusual Process Execution - Temp [prebuilt-rule-8-1-1-unusual-process-execution-temp]

Identifies processes running in a temporary folder. This is sometimes done by adversaries to hide malware.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1973]

```js
event.category:process and event.type:(start or process_started) and process.working_directory:/tmp and
  not process.parent.name:(update-motd-updates-available or
                           apt or apt-* or
                           cnf-update-db or
                           appstreamcli or
                           unattended-upgrade or
                           packagekitd) and
  not process.args:(/usr/lib/update-notifier/update-motd-updates-available or
                    /var/lib/command-not-found/)
```


