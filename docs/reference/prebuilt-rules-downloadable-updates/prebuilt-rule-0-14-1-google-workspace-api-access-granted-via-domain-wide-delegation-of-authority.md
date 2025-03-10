---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-google-workspace-api-access-granted-via-domain-wide-delegation-of-authority.html
---

# Google Workspace API Access Granted via Domain-Wide Delegation of Authority [prebuilt-rule-0-14-1-google-workspace-api-access-granted-via-domain-wide-delegation-of-authority]

Detects when a domain-wide delegation of authority is granted to a service account. Domain-wide delegation can be configured to grant third-party and internal applications to access the data of Google Workspace users. An adversary may configure domain-wide delegation to maintain access to their target’s data.

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

* [https://developers.google.com/admin-sdk/directory/v1/guides/delegation](https://developers.google.com/admin-sdk/directory/v1/guides/delegation)

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

## Investigation guide [_investigation_guide_1273]

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

## Rule query [_rule_query_1346]

```js
event.dataset:(gsuite.admin or google_workspace.admin) and event.provider:admin and event.category:iam and event.action:AUTHORIZE_API_CLIENT_ACCESS
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



