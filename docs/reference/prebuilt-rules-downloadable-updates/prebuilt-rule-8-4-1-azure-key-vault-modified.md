---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-azure-key-vault-modified.html
---

# Azure Key Vault Modified [prebuilt-rule-8-4-1-azure-key-vault-modified]

Identifies modifications to a Key Vault in Azure. The Key Vault is a service that safeguards encryption keys and secrets like certificates, connection strings, and passwords. Because this data is sensitive and business critical, access to key vaults should be secured to allow only authorized applications and users.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts)
* [https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault](https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Data Protection

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2608]



## Rule query [_rule_query_2994]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KEYVAULT/VAULTS/WRITE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Credentials In Files
    * ID: T1552.001
    * Reference URL: [https://attack.mitre.org/techniques/T1552/001/](https://attack.mitre.org/techniques/T1552/001/)



