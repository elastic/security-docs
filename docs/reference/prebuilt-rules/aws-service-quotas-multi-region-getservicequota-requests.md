---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-service-quotas-multi-region-getservicequota-requests.html
---

# AWS Service Quotas Multi-Region `GetServiceQuota` Requests [aws-service-quotas-multi-region-getservicequota-requests]

Identifies when a single AWS resource is making `GetServiceQuota` API calls for the EC2 service quota L-1216C47A in more than 10 regions within a 30-second window. Quota code L-1216C47A represents on-demand instances which are used by adversaries to deploy malware and mine cryptocurrency. This could indicate a potential threat actor attempting to discover the AWS infrastructure across multiple regions using compromised credentials or a compromised instance.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sentinelone.com/labs/exploring-fbot-python-based-malware-targeting-cloud-and-payment-services/](https://www.sentinelone.com/labs/exploring-fbot-python-based-malware-targeting-cloud-and-payment-services/)
* [https://docs.aws.amazon.com/servicequotas/2019-06-24/apireference/API_GetServiceQuota.html](https://docs.aws.amazon.com/servicequotas/2019-06-24/apireference/API_GetServiceQuota.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Service Quotas
* Use Case: Threat Detection
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_104]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Service Quotas Multi-Region `GetServiceQuota` Requests**

AWS Service Quotas manage resource limits across AWS services, crucial for maintaining operational boundaries. Adversaries may exploit `GetServiceQuota` API calls to probe AWS infrastructure, seeking vulnerabilities for deploying threats like cryptocurrency miners. The detection rule identifies unusual multi-region queries for EC2 quotas, signaling potential credential compromise or unauthorized access attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the specific user or role associated with the `aws.cloudtrail.user_identity.arn` field that triggered the alert. Determine if this user or role should have access to multiple regions.
* Examine the `cloud.region` field to identify which regions were accessed and verify if these regions are typically used by your organization. Investigate any unfamiliar regions for unauthorized activity.
* Check the AWS IAM policies and permissions associated with the identified user or role to ensure they align with the principle of least privilege. Look for any recent changes or anomalies in permissions.
* Investigate the source IP addresses and locations from which the `GetServiceQuota` API calls were made to determine if they match expected patterns for your organization. Look for any unusual or suspicious IP addresses.
* Review recent activity logs for the identified user or role to detect any other unusual or unauthorized actions, such as attempts to launch EC2 instances or access other AWS services.
* If a compromise is suspected, consider rotating the credentials for the affected user or role and implementing additional security measures, such as multi-factor authentication (MFA) and enhanced monitoring.

**False positive analysis**

* Legitimate multi-region operations: Organizations with a global presence may have legitimate reasons for querying EC2 service quotas across multiple regions. To handle this, users can create exceptions for known accounts or roles that regularly perform such operations.
* Automated infrastructure management tools: Some tools or scripts designed for infrastructure management might perform multi-region `GetServiceQuota` requests as part of their normal operation. Users should identify these tools and exclude their activity from triggering alerts by whitelisting their associated user identities or ARNs.
* Testing and development activities: Developers or testers might intentionally perform multi-region queries during testing phases. Users can mitigate false positives by setting up temporary exceptions for specific time frames or user identities involved in testing.
* Cloud service providers or partners: Third-party services or partners managing AWS resources on behalf of an organization might generate similar patterns. Users should establish trust relationships and exclude these entities from detection by verifying their activities and adding them to an exception list.

**Response and remediation**

* Immediately isolate the AWS account or IAM user identified in the alert to prevent further unauthorized access. This can be done by disabling the access keys or suspending the account temporarily.
* Conduct a thorough review of the AWS CloudTrail logs for the identified user or resource to determine the extent of the unauthorized activity and identify any other potentially compromised resources.
* Rotate all access keys and passwords associated with the compromised account or IAM user to prevent further unauthorized access.
* Implement additional security measures such as enabling multi-factor authentication (MFA) for all IAM users and roles to enhance account security.
* Notify the security operations team and relevant stakeholders about the potential compromise and the steps being taken to remediate the issue.
* If evidence of compromise is confirmed, consider engaging AWS Support or a third-party incident response team for further investigation and assistance.
* Review and update IAM policies and permissions to ensure the principle of least privilege is enforced, reducing the risk of future unauthorized access attempts.


## Rule query [_rule_query_108]

```js
from logs-aws.cloudtrail-*

// filter for GetServiceQuota API calls
| where event.dataset == "aws.cloudtrail" and event.provider == "servicequotas.amazonaws.com" and event.action == "GetServiceQuota"

// truncate the timestamp to a 30-second window
| eval target_time_window = DATE_TRUNC(30 seconds, @timestamp)

// pre-process the request parameters to extract the service code and quota code
| dissect aws.cloudtrail.request_parameters "{%{?service_code_key}=%{service_code}, %{?quota_code_key}=%{quota_code}}"

// filter for EC2 service quota L-1216C47A (vCPU on-demand instances)
| where service_code == "ec2" and quota_code == "L-1216C47A"

// keep only the relevant fields
| keep target_time_window, aws.cloudtrail.user_identity.arn, cloud.region, service_code, quota_code

// count the number of unique regions and total API calls within the 30-second window
| stats region_count = count_distinct(cloud.region), window_count = count(*) by target_time_window, aws.cloudtrail.user_identity.arn

// filter for resources making DescribeInstances API calls in more than 10 regions within the 30-second window
| where region_count >= 10 and window_count >= 10

// sort the results by time windows in descending order
| sort target_time_window desc
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



