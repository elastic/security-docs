---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-route-53-domain-transfer-lock-disabled.html
---

# AWS Route 53 Domain Transfer Lock Disabled [aws-route-53-domain-transfer-lock-disabled]

Identifies when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html)
* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Route53
* Use Case: Asset Visibility
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_79]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Route 53 Domain Transfer Lock Disabled**

AWS Route 53’s domain transfer lock is a security feature that prevents unauthorized domain transfers. Disabling this lock can expose domains to hijacking risks. Adversaries might exploit this by transferring domains to gain control over web traffic or disrupt services. The detection rule monitors successful lock disablement events, alerting analysts to potential unauthorized actions, thereby aiding in maintaining domain integrity.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.action: DisableDomainTransferLock to identify the user or service account responsible for the action.
* Check the event.provider: route53.amazonaws.com logs to gather additional context about the domain affected and any related activities around the time of the lock disablement.
* Verify the event.outcome: success to confirm that the lock was indeed successfully disabled and not just attempted.
* Investigate the account activity of the user identified in the logs to determine if there are any other suspicious actions or patterns that could indicate unauthorized access.
* Assess whether there was a legitimate business need for the domain transfer lock to be disabled, such as a planned domain transfer, by consulting with relevant stakeholders or reviewing change management records.
* Evaluate the current security posture of the affected domain, ensuring that other security measures are in place to mitigate potential risks from the lock being disabled.

**False positive analysis**

* Routine domain management activities by authorized personnel can trigger alerts when they intentionally disable the transfer lock for legitimate domain transfers. To manage this, maintain a list of authorized personnel and their expected activities, and cross-reference alerts with this list.
* Scheduled domain transfers as part of business operations may result in false positives. Implement a process to document and pre-approve such transfers, allowing security teams to quickly verify and dismiss these alerts.
* Automated scripts or tools used for domain management might inadvertently disable the transfer lock during updates or maintenance. Ensure these tools are configured correctly and include logging to track their actions, allowing for quick identification and exclusion of benign activities.
* Changes in domain ownership or restructuring within the organization can lead to legitimate transfer lock disablement. Establish a communication protocol between IT and security teams to notify them of such changes in advance, reducing unnecessary alerts.

**Response and remediation**

* Immediately verify the legitimacy of the domain transfer request by contacting the domain owner or the responsible team to confirm if the action was intentional.
* If the transfer lock was disabled without authorization, re-enable the transfer lock on the affected domain to prevent any unauthorized transfer attempts.
* Conduct a thorough review of AWS CloudTrail logs to identify any unauthorized access or suspicious activities related to the domain management account.
* Reset credentials and enforce multi-factor authentication (MFA) for all accounts with access to AWS Route 53 to prevent further unauthorized actions.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and coordination for further investigation and response.
* Escalate the incident to higher management and legal teams if there is evidence of malicious intent or if the domain is critical to business operations.
* Implement additional monitoring and alerting for any future changes to domain transfer locks to ensure rapid detection and response to similar threats.


## Setup [_setup_46]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_83]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:DisableDomainTransferLock and event.outcome:success
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



