---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-s3-bucket-enumeration-or-brute-force.html
---

# AWS S3 Bucket Enumeration or Brute Force [aws-s3-bucket-enumeration-or-brute-force]

Identifies a high number of failed S3 operations from a single source and account (or anonymous account) within a short timeframe. This activity can be indicative of attempting to cause an increase in billing to an account for excessive random operations, cause resource exhaustion, or enumerating bucket names for discovery.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://medium.com/@maciej.pocwierz/how-an-empty-s3-bucket-can-make-your-aws-bill-explode-934a383cb8b1](https://medium.com/@maciej.pocwierz/how-an-empty-s3-bucket-can-make-your-aws-bill-explode-934a383cb8b1)
* [https://docs.aws.amazon.com/cli/latest/reference/s3api/](https://docs.aws.amazon.com/cli/latest/reference/s3api/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Resources: Investigation Guide
* Use Case: Log Auditing
* Tactic: Impact

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_84]

**Triage and analysis**

**Investigating AWS S3 Bucket Enumeration or Brute Force**

AWS S3 buckets can be be brute forced to cause financial impact against the resource owner. What makes this even riskier is that even private, locked down buckets can still trigger a potential cost, even with an "Access Denied", while also being accessible from unauthenticated, anonymous accounts. This also appears to work on several or all [operations](https://docs.aws.amazon.com/cli/latest/reference/s3api/) (GET, PUT, list-objects, etc.). Additionally, buckets are trivially discoverable by default as long as the bucket name is known, making it vulnerable to enumeration for discovery.

Attackers may attempt to enumerate names until a valid bucket is discovered and then pivot to cause financial impact, enumerate for more information, or brute force in other ways to attempt to exfil data.

**Possible investigation steps**

* Examine the history of the operation requests from the same `source.address` and `cloud.account.id` to determine if there is other suspicious activity.
* Review similar requests and look at the `user.agent` info to ascertain the source of the requests (though do not overly rely on this since it is controlled by the requestor).
* Review other requests to the same `aws.s3.object.key` as well as other `aws.s3.object.key` accessed by the same `cloud.account.id` or `source.address`.
* Investigate other alerts associated with the user account during the past 48 hours.
* Validate the activity is not related to planned patches, updates, or network administrator activity.
* Examine the request parameters. These may indicate the source of the program or the nature of the task being performed when the error occurred.
* Check whether the error is related to unsuccessful attempts to enumerate or access objects, data, or secrets.
* Considering the source IP address and geolocation of the user who issued the command:
* Do they look normal for the calling user?
* If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source IP from an EC2 instance that’s not under your control?
* If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
* Consider the time of day. If the user is a human (not a program or script), did the activity take place during a normal time of day?
* Contact the account owner and confirm whether they are aware of this activity if suspicious.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

**False positive analysis**

* Verify the `source.address` and `cloud.account.id` - there are some valid operations from within AWS directly that can cause failures and false positives. Additionally, failed automation can also caeuse false positives, but should be identifiable by reviewing the `source.address` and `cloud.account.id`.

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
* Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
* Consider enabling multi-factor authentication for users.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
* Take the actions needed to return affected systems, data, or services to their normal operational levels.
* Identify the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
* Check for PutBucketPolicy event actions as well to see if they have been tampered with. While we monitor for denied, a single successful action to add a backdoor into the bucket via policy updates (however they got permissions) may be critical to identify during TDIR.


## Rule query [_rule_query_88]

```js
from logs-aws.cloudtrail*
| where event.provider == "s3.amazonaws.com" and aws.cloudtrail.error_code == "AccessDenied"
// keep only relevant fields
| keep tls.client.server_name, source.address, cloud.account.id
| stats failed_requests = count(*) by tls.client.server_name, source.address, cloud.account.id
  // can modify the failed request count or tweak time window to fit environment
  // can add `not cloud.account.id in (KNOWN)` or specify in exceptions
| where failed_requests > 40
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Financial Theft
    * ID: T1657
    * Reference URL: [https://attack.mitre.org/techniques/T1657/](https://attack.mitre.org/techniques/T1657/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Infrastructure Discovery
    * ID: T1580
    * Reference URL: [https://attack.mitre.org/techniques/T1580/](https://attack.mitre.org/techniques/T1580/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)



