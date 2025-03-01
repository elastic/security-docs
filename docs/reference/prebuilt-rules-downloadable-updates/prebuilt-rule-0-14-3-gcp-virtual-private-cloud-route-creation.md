---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-gcp-virtual-private-cloud-route-creation.html
---

# GCP Virtual Private Cloud Route Creation [prebuilt-rule-0-14-3-gcp-virtual-private-cloud-route-creation]

Identifies when a Virtual Private Cloud a virtual private cloud (VPC) route is created in Google Cloud Platform (GCP). Google Cloud routes define the paths that network traffic takes from a virtual machine (VM) instance to other destinations. These destinations can be inside a Google VPC network or outside it. An adversary may create a route in order to impact the flow of network traffic in their target’s cloud environment.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/vpc/docs/routes](https://cloud.google.com/vpc/docs/routes)
* [https://cloud.google.com/vpc/docs/using-routes](https://cloud.google.com/vpc/docs/using-routes)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1345]

## Config

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1523]

```js
event.dataset:(googlecloud.audit or gcp.audit) and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
```


