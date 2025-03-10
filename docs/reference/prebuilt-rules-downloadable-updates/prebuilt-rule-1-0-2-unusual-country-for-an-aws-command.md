---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-unusual-country-for-an-aws-command.html
---

# Unusual Country For an AWS Command [prebuilt-rule-1-0-2-unusual-country-for-an-aws-command]

A machine learning job detected AWS command activity that, while not inherently suspicious or abnormal, is sourcing from a geolocation (country) that is unusual for the command. This can be the result of compromised credentials or keys being used by a threat actor in a different geography than the authorized user(s).

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-2h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_1407]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Triage and analysis

## Investigating an Unusual Country For an AWS Command

CloudTrail logging provides visibility on actions taken within an AWS environment. By monitoring these events and understanding
what is considered normal behavior within an organization, suspicious or malicious activity can be spotted when deviations
are observed. This example rule focuses on AWS command activity where the country from the source of the activity has been
considered unusual based on previous history.

### Possible investigation steps:
- Consider the source IP address and geolocation for the calling user who issued the command. Do they look normal for the calling user? If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts, or could it be sourcing from an EC2 instance that's not under your control? If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
- Consider the user as identified by the `user.name` field. Is this command part of an expected workflow for the user context? Examine the user identity in the `aws.cloudtrail.user_identity.arn` field and the access key ID in the `aws.cloudtrail.user_identity.access_key_id` field, which can help identify the precise user context. The user agent details in the `user_agent.original` field may also indicate what kind of a client made the request.
- Consider the time of day. If the user is a human, not a program or script, did the activity take place during a normal time of day?
- Examine the history of the command. If the command, which is visible in the `event.action field`, only manifested recently, it might be part of a new automation module or script. If it has a consistent cadence (for example, if it appears in small numbers on a weekly or monthly cadence), it might be part of a housekeeping or maintenance process.
- Examine the request parameters. These may provide indications as to the source of the program or the nature of the tasks it is performing.

## False Positive Analysis
- False positives can occur if activity is coming from new employees based in a country with no previous history in AWS,
therefore it's important to validate the activity listed in the investigation steps above.

## Related Rules
- Unusual City For an AWS Command
- Unusual AWS Command for a User
- Rare AWS Error Code

## Response and Remediation
- If suspicious or malicious activity is observed, immediately rotate and delete relevant AWS IAM access keys.
- Validate if any unauthorized new users were created, remove these accounts and request password resets for other IAM users.
- Look into enabling multi-factor authentication for users.
- Follow security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.

