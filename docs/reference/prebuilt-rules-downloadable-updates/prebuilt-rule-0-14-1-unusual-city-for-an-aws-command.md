---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-unusual-city-for-an-aws-command.html
---

# Unusual City For an AWS Command [prebuilt-rule-0-14-1-unusual-city-for-an-aws-command]

A machine learning job detected AWS command activity that, while not inherently suspicious or abnormal, is sourcing from a geolocation (city) that is unusual for the command. This can be the result of compromised credentials or keys being used by a threat actor in a different geography than the authorized user(s).

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

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1261]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Triage and analysis

## Investigating an Unusual CloudTrail Event
Detection alerts from this rule indicate an AWS API command or method call that is rare and unusual for the geolocation of the source IP address. Here are some possible avenues of investigation:
- Consider the source IP address and geolocation for the calling user who issued the command. Do they look normal for the calling user? If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts, or could it be sourcing from an EC2 instance not under your control? If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
- Consider the user as identified by the `user.name` field. Is this command part of an expected workflow for the user context? Examine the user identity in the `aws.cloudtrail.user_identity.arn` field and the access key id in the `aws.cloudtrail.user_identity.access_key_id` field, which can help identify the precise user context. The user agent details in the `user_agent.original` field may also indicate what kind of a client made the request.
- Consider the time of day. If the user is a human, not a program or script, did the activity take place during a normal time of day?
- Examine the history of the command. If the command, which is visible in the `event.action field`, only manifested recently, it might be part of a new automation module or script. If it has a consistent cadence (for example, if it appears in small numbers on a weekly or monthly cadence), it might be part of a housekeeping or maintenance process.
- Examine the request parameters. These may provide indications as to the source of the program or the nature of the tasks it is performing.

