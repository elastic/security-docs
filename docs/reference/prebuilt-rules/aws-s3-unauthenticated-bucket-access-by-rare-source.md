---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-s3-unauthenticated-bucket-access-by-rare-source.html
---

# AWS S3 Unauthenticated Bucket Access by Rare Source [aws-s3-unauthenticated-bucket-access-by-rare-source]

Identifies AWS CloudTrail events where an unauthenticated source is attempting to access an S3 bucket. This activity may indicate a misconfigured S3 bucket policy that allows public access to the bucket, potentially exposing sensitive data to unauthorized users. Adversaries can specify `--no-sign-request` in the AWS CLI to retrieve objects from an S3 bucket without authentication. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule, which means it will only trigger once for each unique value of the `source.address` field that has not been seen making this API request within the last 7 days. This field contains the IP address of the source making the request.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: Amazon S3
* Use Case: Asset Visibility
* Resources: Investigation Guide
* Tactic: Collection

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_91]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS S3 Unauthenticated Bucket Access by Rare Source**

Amazon S3 is a scalable storage service used for data storage and retrieval. Misconfigured bucket policies can inadvertently allow public access, posing a risk of unauthorized data exposure. Adversaries exploit this by using unauthenticated requests to access data. The detection rule identifies unusual access attempts from new IP addresses, signaling potential misuse and prompting further investigation.

**Possible investigation steps**

* Review the CloudTrail logs to identify the specific S3 bucket involved in the unauthenticated access attempt and determine the nature of the accessed data.
* Examine the source IP address from the `source.address` field to assess its origin and determine if it is associated with known malicious activity or if it is a legitimate but misconfigured source.
* Check the S3 bucket policy and permissions to identify any misconfigurations that might allow public access, focusing on policies that include "Principal": "*".
* Investigate the `aws.cloudtrail.user_identity.type` field to confirm if the access was made by an "AWSAccount" or "Unknown" identity, and determine if this aligns with expected behavior.
* Assess the `event.action` field to understand the type of operation performed (e.g., "GetObject", "PutObject") and evaluate the potential impact of the access.
* Review recent changes to the S3 bucket configuration or IAM policies that might have inadvertently allowed public access, and correlate these with the timing of the alert.
* If unauthorized access is confirmed, take immediate steps to secure the bucket by updating the bucket policy to restrict access and consider enabling logging and monitoring for future access attempts.

**False positive analysis**

* Frequent access from known internal IP addresses may trigger the rule. To manage this, create exceptions for IP addresses that are part of your organization’s network and regularly access S3 buckets without authentication.
* Automated scripts or tools used for legitimate business processes might use unauthenticated requests. Identify these scripts and exclude their IP addresses from triggering the rule by adding them to an allowlist.
* Third-party services that require access to your S3 buckets might appear as unauthenticated sources. Verify these services and, if deemed safe, exclude their IP addresses from the rule to prevent false positives.
* Temporary testing environments or development setups might use unauthenticated access for convenience. Ensure these environments are documented and their IP addresses are excluded from the rule to avoid unnecessary alerts.

**Response and remediation**

* Immediately revoke public access to the affected S3 bucket by updating the bucket policy to restrict access to only authorized users and roles.
* Identify and terminate any unauthorized sessions or connections from the IP addresses flagged in the alert to prevent further unauthorized access.
* Conduct a thorough review of the S3 bucket’s access logs to determine the extent of data exposure and identify any sensitive data that may have been accessed.
* Notify the security team and relevant stakeholders about the potential data exposure incident and provide them with details of the affected resources and actions taken.
* Implement additional monitoring and alerting for unusual access patterns to S3 buckets, focusing on unauthenticated access attempts and access from rare IP addresses.
* Escalate the incident to the organization’s incident response team for further investigation and to determine if additional containment or remediation actions are necessary.
* Review and update the organization’s cloud security policies and access controls to prevent similar misconfigurations in the future, ensuring that all S3 buckets have appropriate access restrictions.

**Investigating AWS S3 Unauthenticated Bucket Access by Rare Source**

This rule detects requests to an AWS S3 bucket by an unauthenticated source, which could indicate a misconfigured bucket policy allowing public access. Adversaries can exploit this misconfiguration by using tools or AWS CLI options like `--no-sign-request` to access bucket contents.

The rule triggers when an unauthenticated IP address retrieves an object, and that IP has not been seen in the last 7 days.

**Possible Investigation Steps**

1. ***Identify the Source of the Request***:

    * Review the `source.address` field to determine the IP address of the request source.
    * Check `source.geo` fields for geographic details of the originating IP address.
    * Analyze the `user_agent.original` field to identify the client or tool used (e.g., `Python Requests`, `aws-cli`, browser).

2. ***Review the Accessed Bucket and Object***:

    * Analyze the `aws.cloudtrail.resources.arn` field to identify the S3 bucket and object being accessed.
    * Inspect `aws.cloudtrail.request_parameters` for bucket name and object key to determine which file was retrieved.
    * Review the `even.action` field to identify which API call was made (e.g., `GetObject`, `ListObjects`, `PutObject`, `ListBucket`).

3. ***Validate the Source IP and Context***:

    * Determine if the IP address (`source.address`) has any prior activity in your environment.
    * Correlate the IP with threat intelligence or blocklist databases to check for malicious indicators.
    * Review CloudTrail logs for other activities originating from the same IP.

4. ***Analyze the S3 Bucket Configuration***:

    * Review the S3 bucket’s Access Control List (ACL) and bucket policy to check for misconfigurations allowing public or unauthenticated access.
    * Look for overly permissive settings, such as `Principal: *` or `Effect: Allow` rules that expose the bucket.

5. ***Investigate Additional Activity***:

    * Check if there are subsequent actions, such as:
    * ***Additional `GetObject` API calls***: Indicating further data exfiltration.
    * ***ListObjects requests***: Attempting to enumerate the bucket’s contents.
    * Correlate events within the same timeframe to identify related suspicious activity.

6. ***Assess the Data Exposed***:

    * Identify the retrieved object(s) and analyze their content to assess potential data exposure.
    * Determine if the file contains sensitive information, such as credentials, intellectual property, or PII.


**False Positive Analysis**

* ***Public Buckets by Design***: Some S3 buckets may intentionally allow public access. Verify with the bucket owner if the access was expected.
* ***Automated Tools***: Security scanners or legitimate services may generate `GetObject` events to validate bucket configurations.

**Response and Remediation**

1. ***Immediate Action***:

    * Restrict or remove public access to the affected S3 bucket.
    * Update the bucket policy to ensure access is restricted to trusted principals.
    * Enable ***S3 Block Public Access*** settings to prevent unintended public access.

2. ***Monitoring and Detection***:

    * Enable detailed logging and monitoring for all S3 bucket activities.
    * Configure real-time alerts for unauthenticated `GetObject` or `ListObjects` events on sensitive S3 buckets.

3. ***Security Audits***:

    * Regularly audit S3 bucket policies and ACLs to ensure they adhere to AWS security best practices.
    * Use AWS tools like ***Trusted Advisor*** or ***Access Analyzer*** to identify and address misconfigurations.

4. ***Investigate for Data Exfiltration***:

    * Analyze historical CloudTrail logs to determine if other sensitive files were accessed or exfiltrated.
    * Assess the scope of the exposure and initiate further response if sensitive data was compromised.


**Additional Resources**

* [AWS Documentation: S3 Bucket Policy Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
* [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)


## Rule query [_rule_query_95]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "s3.amazonaws.com"
    and event.action: (
        "GetObject" or
        "PutObject" or
        "ListObjects" or
        "DeleteObject" or
        "ListBucket")
    and event.outcome: "success"
    and aws.cloudtrail.user_identity.type: ("AWSAccount" or "Unknown")
    and cloud.account.id: "anonymous"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Storage Object Discovery
    * ID: T1619
    * Reference URL: [https://attack.mitre.org/techniques/T1619/](https://attack.mitre.org/techniques/T1619/)

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



