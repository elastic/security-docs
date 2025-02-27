---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-google-workspace-admin-role-deletion.html
---

# Google Workspace Admin Role Deletion [prebuilt-rule-0-14-1-google-workspace-admin-role-deletion]

Detects when a custom admin role is deleted. An adversary may delete a custom admin role in order to impact the permissions or capabilities of system administrators.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/2406043?hl=en](https://support.google.com/a/answer/2406043?hl=en)

**Tags**:

* Elastic
* Cloud
* Google Workspace
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1268]

## Config

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - https://www.elastic.co/guide/en/beats/filebeat/8.17/filebeat-module-google_workspace.html

## Rule query [_rule_query_1341]

```js
event.dataset:(gsuite.admin or google_workspace.admin) and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```


