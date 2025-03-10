---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-discovery-api-calls-via-cli-from-a-single-resource.html
---

# AWS Discovery API Calls via CLI from a Single Resource [aws-discovery-api-calls-via-cli-from-a-single-resource]

Detects when a single AWS resource is running multiple `Describe` and `List` API calls in a 10-second window. This behavior could indicate an actor attempting to discover the AWS infrastructure using compromised credentials or a compromised instance. Adversaries may use this information to identify potential targets for further exploitation or to gain a better understanding of the target’s infrastructure.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: AWS EC2
* Data Source: AWS IAM
* Data Source: AWS S3
* Use Case: Threat Detection
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_21]

**Triage and analysis**

**Investigating AWS Discovery API Calls via CLI from a Single Resource**

This rule detects multiple discovery-related API calls (`Describe`, `List`, or `Get` actions) within a short time window (30 seconds) from a single AWS resource. High volumes of such calls may indicate attempts to enumerate AWS infrastructure for reconnaissance purposes, which is often a tactic used by adversaries with compromised credentials or unauthorized access.

**Possible Investigation Steps**

* ***Identify the Actor and Resource***:
* ***User Identity and Resource***: Examine `aws.cloudtrail.user_identity.arn` to identify the actor making the discovery requests. Verify the user or resource associated with these actions to ensure they are recognized and expected.
* ***User Agent and Tooling***: Check `user_agent.name` to confirm whether the `aws-cli` tool was used for these requests. Use of the CLI in an atypical context might indicate unauthorized or automated access.
* ***Evaluate the Context and Scope of API Calls***:
* ***API Action Types***: Look into the specific actions under `event.action` for API calls like `Describe*`, `List*`, or `Get*`. Note if these calls are targeting sensitive services, such as `EC2`, `IAM`, or `S3`, which may suggest an attempt to identify high-value assets.
* ***Time Pattern Analysis***: Review the `time_window` and `unique_api_count` to assess whether the frequency of these calls is consistent with normal patterns for this resource or user.
* ***Analyze Potential Compromise Indicators***:
* ***Identity Type***: Review `aws.cloudtrail.user_identity.type` to determine if the calls originated from an assumed role, a root user, or a service role. Unusual identity types for discovery operations may suggest misuse or compromise.
* ***Source IP and Geographic Location***: Examine the `source.ip` and `source.geo` fields to identify any unusual IP addresses or locations associated with the activity, which may help confirm or rule out external access.
* ***Examine Related CloudTrail Events***:
* ***Pivot for Related Events***: Identify any additional IAM or CloudTrail events tied to the same actor ARN. Activities such as `AssumeRole`, `GetSessionToken`, or `CreateAccessKey` in proximity to these discovery calls may signal an attempt to escalate privileges.
* ***Look for Anomalous Patterns***: Determine if this actor or resource has performed similar discovery actions previously, or if these actions coincide with other alerts related to credential use or privilege escalation.

**False Positive Analysis**

* ***Expected Discovery Activity***: Regular discovery or enumeration API calls may be conducted by security, automation, or monitoring scripts to maintain an inventory of resources. Validate if this activity aligns with known automation or inventory tasks.
* ***Routine Admin or Automated Access***: If specific roles or resources, such as automation tools or monitoring services, regularly trigger this rule, consider adding exceptions for these known, benign users to reduce false positives.

**Response and Remediation**

* ***Confirm Authorized Access***: If the discovery activity appears unauthorized, consider immediate steps to restrict the user or resource’s permissions.
* ***Review and Remove Unauthorized API Calls***: If the actor is not authorized to perform discovery actions, investigate and potentially disable their permissions or access keys to prevent further misuse.
* ***Enhance Monitoring for Discovery Patterns***: Consider additional logging or alerting for high-frequency discovery API calls, especially if triggered from new or unrecognized resources.
* ***Policy Review and Updates***: Review IAM policies associated with the actor, ensuring restrictive permissions and MFA enforcement where possible to prevent unauthorized discovery.

**Additional Information**

For further guidance on AWS infrastructure discovery and best practices, refer to [AWS CloudTrail documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.md) and MITRE ATT&CK’s [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/).


## Rule query [_rule_query_21]

```js
from logs-aws.cloudtrail*

// create time window buckets of 10 seconds
| eval time_window = date_trunc(10 seconds, @timestamp)
| where
    event.dataset == "aws.cloudtrail"

    // filter on CloudTrail audit logs for IAM, EC2, and S3 events only
    and event.provider in (
      "iam.amazonaws.com",
      "ec2.amazonaws.com",
      "s3.amazonaws.com",
      "rds.amazonaws.com",
      "lambda.amazonaws.com",
      "dynamodb.amazonaws.com",
      "kms.amazonaws.com",
      "cloudfront.amazonaws.com",
      "elasticloadbalancing.amazonaws.com",
      "cloudfront.amazonaws.com"
    )

    // ignore AWS service actions
    and aws.cloudtrail.user_identity.type != "AWSService"

    // filter for aws-cli specifically
    and user_agent.name == "aws-cli"

    // exclude DescribeCapacityReservations events related to AWS Config
    and not event.action in ("DescribeCapacityReservations")

// filter for Describe, Get, List, and Generate API calls
| where true in (
    starts_with(event.action, "Describe"),
    starts_with(event.action, "Get"),
    starts_with(event.action, "List"),
    starts_with(event.action, "Generate")
)
// extract owner, identity type, and actor from the ARN
| dissect aws.cloudtrail.user_identity.arn "%{}::%{owner}:%{identity_type}/%{actor}"
| where starts_with(actor, "AWSServiceRoleForConfig") != true
| keep @timestamp, time_window, event.action, aws.cloudtrail.user_identity.arn
| stats
    // count the number of unique API calls per time window and actor
    unique_api_count = count_distinct(event.action) by time_window, aws.cloudtrail.user_identity.arn

// filter for more than 5 unique API calls per time window
| where unique_api_count > 5

// sort the results by the number of unique API calls in descending order
| sort unique_api_count desc
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Infrastructure Discovery
    * ID: T1580
    * Reference URL: [https://attack.mitre.org/techniques/T1580/](https://attack.mitre.org/techniques/T1580/)



