---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/domain-added-to-google-workspace-trusted-domains.html
---

# Domain Added to Google Workspace Trusted Domains [domain-added-to-google-workspace-trusted-domains]

Detects when a domain is added to the list of trusted Google Workspace domains. An adversary may add a trusted domain in order to collect and exfiltrate data from their target’s organization with less restrictive security controls.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/6160020?hl=en](https://support.google.com/a/answer/6160020?hl=en)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_274]

**Triage and analysis**

**Investigating Domain Added to Google Workspace Trusted Domains**

Organizations use trusted domains in Google Workspace to give external users access to resources.

A threat actor with administrative privileges may be able to add a malicious domain to the trusted domain list. Based on the configuration, potentially sensitive resources may be exposed or accessible by an unintended third-party.

This rule detects when a third-party domain is added to the list of trusted domains in Google Workspace.

**Possible investigation steps**

* Identify the associated user accounts by reviewing `user.name` or `user.email` fields in the alert.
* After identifying the user, verify if the user should have administrative privileges to add external domains.
* Check the `google_workspace.admin.domain.name` field to find the newly added domain.
* Use reputational services, such as VirusTotal, for the trusted domain’s third-party intelligence reputation.
* Filter your data. Create a filter where `event.dataset` is `google_workspace.drive` and `google_workspace.drive.file.owner.email` is being compared to `user.email`.
* If mismatches are identified, this could indicate access from an external Google Workspace domain.

**False positive analysis**

* Verify that the user account should have administrative privileges that allow them to edit trusted domains in Google Workspace.
* Talk to the user to evaluate why they added the third-party domain and if the domain has confidentiality risks.

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


## Setup [_setup_176]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_286]

```js
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_TRUSTED_DOMAINS
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

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



