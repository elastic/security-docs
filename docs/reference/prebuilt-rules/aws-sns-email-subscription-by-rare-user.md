---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-sns-email-subscription-by-rare-user.html
---

# AWS SNS Email Subscription by Rare User [aws-sns-email-subscription-by-rare-user]

Identifies when an SNS topic is subscribed to by an email address of a user who does not typically perform this action. Adversaries may subscribe to an SNS topic to collect sensitive information or exfiltrate data via an external email address.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html](https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS SNS
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Exfiltration

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_92]

**Triage and analysis**

**Investigating AWS SNS Email Subscription by Rare User**

This rule identifies when an SNS topic is subscribed to by an email address of a user who does not typically perform this action. While subscribing to SNS topics is a common practice, adversaries may exploit this feature to collect sensitive information or exfiltrate data via an external email address.

**Possible Investigation Steps**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` field to identify the user who requested the subscription. Verify if this actor typically performs such actions and has the necessary permissions. It may be unusual for this activity to originate from certain user types, such as an assumed role or federated user.
* ***Review the SNS Subscription Event***: Analyze the specifics of the `Subscribe` action in CloudTrail logs:
* ***Topic***: Look at the `aws.cloudtrail.request_parameters.topicArn` field to identify the SNS topic involved in the subscription.
* ***Protocol and Endpoint***: Review the `aws.cloudtrail.request_parameters.protocol` and `aws.cloudtrail.request_parameters.endpoint` fields to confirm the subscription’s protocol and email address. Confirm if this endpoint is associated with a known or trusted entity.
* ***Subscription Status***: Check the `aws.cloudtrail.response_elements.subscriptionArn` field for the subscription’s current status, noting if it requires confirmation.
* ***Verify Authorization***: Evaluate whether the user typically engages in SNS subscription actions and if they are authorized to do so for the specified topic.
* ***Contextualize with Related Events***: Review related CloudTrail logs around the event time for other actions by the same user or IP address. Look for activities involving other AWS services, such as S3 or IAM, that may indicate further suspicious behavior.
* ***Evaluate the Subscription Endpoint***: Determine whether the email endpoint is legitimate or associated with any known entity. This may require checking internal documentation or reaching out to relevant AWS account administrators.
* ***Check for Publish Actions***: Investigate for any subsequent `Publish` actions on the same SNS topic that may indicate exfiltration attempts or data leakage. If Publish actions are detected, further investigate the contents of the messages.
* ***Review IAM Policies***: Examine the user or role’s IAM policies to ensure that the subscription action is within the scope of their permissions or should be.

**False Positive Analysis**

* ***Historical User Actions***: Verify if the user has a history of performing similar actions on SNS topics. Consistent, repetitive actions may suggest legitimate usage.
* ***Scheduled or Automated Tasks***: Confirm if the subscription action aligns with scheduled tasks or automated notifications authorized by your organization.

**Response and Remediation**

* ***Immediate Review and Reversal***: If the subscription was unauthorized, take appropriate action to cancel it and adjust SNS permissions as necessary.
* ***Strengthen Monitoring and Alerts***: Configure monitoring systems to flag similar actions involving sensitive topics or unapproved endpoints.
* ***Policy Review***: Review and update policies related to SNS subscriptions and access, tightening control as needed to prevent unauthorized subscriptions.
* ***Incident Response***: If there is evidence of malicious intent, treat the event as a potential data exfiltration incident and follow incident response protocols, including further investigation, containment, and recovery.

**Additional Information**

For further guidance on managing and securing SNS topics in AWS environments, refer to the [AWS SNS documentation](https://docs.aws.amazon.com/sns/latest/dg/welcome.md) and AWS best practices for security.


## Rule query [_rule_query_96]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "sns.amazonaws.com"
    and event.action: "Subscribe"
    and aws.cloudtrail.request_parameters: *protocol=email*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Web Service
    * ID: T1567
    * Reference URL: [https://attack.mitre.org/techniques/T1567/](https://attack.mitre.org/techniques/T1567/)



