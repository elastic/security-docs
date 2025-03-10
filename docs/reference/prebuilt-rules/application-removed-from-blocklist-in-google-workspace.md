---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/application-removed-from-blocklist-in-google-workspace.html
---

# Application Removed from Blocklist in Google Workspace [application-removed-from-blocklist-in-google-workspace]

Google Workspace administrators may be aware of malicious applications within the Google marketplace and block these applications for user security purposes. An adversary, with administrative privileges, may remove this application from the explicit block list to allow distribution of the application amongst users. This may also indicate the unauthorized use of an application that had been previously blocked before by a user with admin privileges.

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

* [https://support.google.com/a/answer/6328701?hl=en#](https://support.google.com/a/answer/6328701?hl=en#)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Configuration Audit
* Resources: Investigation Guide
* Tactic: Defense Evasion

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_139]

**Triage and analysis**

**Investigating Application Removed from Blocklist in Google Workspace**

Google Workspace Marketplace is an online store for free and paid web applications that work with Google Workspace services and third-party software. Listed applications are based on Google APIs or Google Apps Script and created by both Google and third-party developers.

Marketplace applications require access to specific Google Workspace resources. Individual users with the appropriate permissions can install applications in their Google Workspace domain. Administrators have additional permissions that allow them to install applications for an entire Google Workspace domain. Consent screens typically display permissions and privileges the user needs to install an application. As a result, malicious Marketplace applications may require more permissions than necessary or have malicious intent.

Google clearly states that they are not responsible for any Marketplace product that originates from a source that isn’t Google.

This rule identifies a Marketplace blocklist update that consists of a Google Workspace account with administrative privileges manually removing a previously blocked application.

**Possible investigation steps**

* Identify the associated user accounts by reviewing `user.name` or `user.email` fields in the alert.
* This rule relies on data from `google_workspace.admin`, thus indicating the associated user has administrative privileges to the Marketplace.
* With access to the Google Workspace admin console, visit the `Security > Investigation` tool with filters for the user email and event is `Assign Role` or `Update Role` to determine if new cloud roles were recently updated.
* After identifying the involved user account, review other potentially related events within the last 48 hours.
* Re-assess the permissions and reviews of the Marketplace applications to determine if they violate organizational policies or introduce unexpected risks.
* With access to the Google Workspace admin console, determine if the application was installed domain-wide or individually by visiting `Apps > Google Workspace Marketplace Apps`.

**False positive analysis**

* Google Workspace administrators might intentionally remove an application from the blocklist due to a re-assessment or a domain-wide required need for the application.
* Identify the user account associated with this action and assess their administrative privileges with Google Workspace Marketplace.
* Contact the user to verify that they intentionally removed the application from the blocklist and their reasoning.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Assess the criticality of affected services and servers.
* Work with your IT team to identify and minimize the impact on users.
* Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
* Identify any regulatory or legal ramifications related to this activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords or delete API keys as needed to revoke the attacker’s access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://support.google.com/a/answer/7587183) by Google.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_79]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_141]

```js
event.dataset:"google_workspace.admin" and event.category:"iam" and event.type:"change"  and
  event.action:"CHANGE_APPLICATION_SETTING" and
  google_workspace.admin.application.name:"Google Workspace Marketplace" and
  google_workspace.admin.old_value: *allowed*false* and google_workspace.admin.new_value: *allowed*true*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



