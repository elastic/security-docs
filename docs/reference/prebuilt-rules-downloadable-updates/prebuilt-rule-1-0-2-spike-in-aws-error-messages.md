---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-spike-in-aws-error-messages.html
---

# Spike in AWS Error Messages [prebuilt-rule-1-0-2-spike-in-aws-error-messages]

A machine learning job detected a significant spike in the rate of a particular error in the CloudTrail messages. Spikes in error messages may accompany attempts at privilege escalation, lateral movement, or discovery.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Elastic
* Cloud
* AWS
* ML

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1406]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Triage and analysis

## Investigating Spikes in CloudTrail Errors

CloudTrail logging provides visibility on actions taken within an AWS environment. By monitoring these events and understanding
what is considered normal behavior within an organization, you can spot suspicious or malicious activity when deviations
occur. This example rule triggers from a large spike in the number of CloudTrail log messages that contain a particular
error message. The error message in question was associated with the response to an AWS API command or method call, this
has the potential to uncover unknown threats or activity.

### Possible investigation steps:
- Examine the history of the error. Has it manifested before? If the error, which is visible in the `aws.cloudtrail.error_message` field, only manifested recently, it might be related to recent changes in an automation module or script.
- Examine the request parameters. These may provide indications as to the nature of the task being performed when the error occurred. Is the error related to unsuccessful attempts to enumerate or access objects, data, or secrets? If so, this can sometimes be a byproduct of discovery, privilege escalation or lateral movement attempts.
- Consider the user as identified by the `user.name field`. Is this activity part of an expected workflow for the user context? Examine the user identity in the `aws.cloudtrail.user_identity.arn` field and the access key ID in the `aws.cloudtrail.user_identity.access_key_id` field, which can help identify the precise user context. The user agent details in the `user_agent.original` field may also indicate what kind of a client made the request.
- Consider the source IP address and geolocation for the calling user who issued the command. Do they look normal for the calling user? If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts, or could it be sourcing from an EC2 instance that's not under your control? If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?

## False Positive Analysis
- This rule has the possibility to produce false positives based on unexpected activity occurring such as bugs or recent
changes to automation modules or scripting.
- The adoption of new services or the addition of new functionality to scripts may generate false positives.

## Related Rules
- Unusual AWS Command for a User
- Rare AWS Error Code

## Response and Remediation
- If suspicious or malicious activity is observed, immediately rotate and delete relevant AWS IAM access keys.
- If any unauthorized new user accounts were created, remove them. Request password resets for other IAM users.
- Look into enabling multi-factor authentication for users.
- Follow security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.

