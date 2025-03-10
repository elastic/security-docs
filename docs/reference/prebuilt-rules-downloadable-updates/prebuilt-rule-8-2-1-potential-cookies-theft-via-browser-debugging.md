---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-potential-cookies-theft-via-browser-debugging.html
---

# Potential Cookies Theft via Browser Debugging [prebuilt-rule-8-2-1-potential-cookies-theft-via-browser-debugging]

Identifies the execution of a Chromium based browser with the debugging process argument, which may indicate an attempt to steal authentication cookies. An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**:

* [https://github.com/defaultnamehere/cookie_crimes](https://github.com/defaultnamehere/cookie_crimes)
* [https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/](https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/)
* [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/chrome_cookies.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/chrome_cookies.md)
* [https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)

**Tags**:

* Elastic
* Host
* Linux
* Windows
* macOS
* Threat Detection
* Credential Access

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1818]



## Rule query [_rule_query_2108]

```js
process where event.type in ("start", "process_started", "info") and
  process.name in (
             "Microsoft Edge",
             "chrome.exe",
             "Google Chrome",
             "google-chrome-stable",
             "google-chrome-beta",
             "google-chrome",
             "msedge.exe") and
   process.args : ("--remote-debugging-port=*",
                   "--remote-debugging-targets=*",
                   "--remote-debugging-pipe=*") and
   process.args : "--user-data-dir=*" and not process.args:"--remote-debugging-port=0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Web Session Cookie
    * ID: T1539
    * Reference URL: [https://attack.mitre.org/techniques/T1539/](https://attack.mitre.org/techniques/T1539/)



