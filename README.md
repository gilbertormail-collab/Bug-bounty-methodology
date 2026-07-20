### Bug bounty methodology

This is my own comprehensive bug bounty methodology for reconisance and explotation. Currently all the `Recon` folder is finished so far and Exploitation will be created soon, archived were my templates/first drafts. This guide is tailored to my own setup on Linux mint however anyone can follow it and setup a similar environment. Refer to the setup guide to setup all the nessarsary tools.

---

### File structure
The file structure should be as follows for each program:
```
target.com/
│
├── recon/
│   │
│   ├── automatic-recon/
│   │   │
│   │   ├── notes.md
│   │   ├── domains.txt
│   │   ├── domains-subfinder.txt
│   │   ├── domains-dnsx.txt
│   │   ├── domains-manual.txt
│   │   ├── live.txt
│   │   ├── live-with-info.txt
│   │   ├── live-hosts.txt
│   │   ├── ffuf-vhosts.json
│   │   ├── dorks.txt
│   │   ├── technology/
│   │   │  ├── httpx.jsonl
│   │   │  ├── technology-inventory.tsv
│   │   │  ├── technology-leads.txt
│   │   │  └── whatweb.txt
│   │   ├── endpoints/
│   │   │  ├── endpoints.txt
│   │   │  ├── params-urls.txt
│   │   │  └── params.txt
│   │   ├── javascript/
│   │   │  ├── js-files.txt
│   │   │  ├── live-js-files.txt
│   │   │  ├── links.txt
│   │   │  ├── secrets.txt
│   │   │  ├── source-maps.txt
│   │   │  ├── api-findings.txt
│   │   │  ├── client-side-findings.txt
│   │   │  ├── js-files/
│   │   │  └── source-maps/
│   │   └── vulnerability_scans/
│   │       ├── nmap-scan.txt
│   │       ├── subdomain-takeover-scan.txt
│   │       └── vulnerabilitys/
│   │           ├── xss.txt
│   │           ├── aws-keys.txt
│   │           ├── cors.txt
│   │           ├── debug-pages.txt
│   │           ├── debug-logic.txt
│   │           ├── firebase.txt
│   │           ├── idor.txt
│   │           ├── http-auth.txt
│   │           ├── img-traversal.txt
│   │           ├── interestingEXT.txt
│   │           ├── interestingparams.txt
│   │           ├── interestingsubs.txt
│   │           ├── lfi.txt
│   │           ├── rce.txt
│   │           ├── redirect.txt
│   │           ├── s3-buckets.txt
│   │           ├── sqli.txt
│   │           ├── ssrf.txt
│   │           ├── ssti.txt
│   │           ├── takeovers.txt
│   │           └── php-sinks.txt
│   │
│   └── manual-recon/
│       │
│       ├── notes.md
│       ├── interesting-endpoints.md
│       └── interesting_subdomain_name/
│           ├── all-endpoints.txt
│           ├── interesting-endpoints.md
│           ├── cloud_storage.md
│           ├── authentication.md
│           ├── authorization.md
│           ├── business-logic.md
│           ├── api-notes.md
│           ├── javascript-review.md
│           └── technology-notes.md
│
├── exploitation/
│   │
│   ├── xss.md
│   ├── sqli.md
│   ├── ssrf.md
│   ├── csrf.md
│   ├── idor.md
│   ├── xxe.md
│   ├── lfi.md
│   ├── rfi.md
│   ├── rce.md
│   ├── ssti.md
│   ├── open-redirect.md
│   ├── clickjacking.md
│   ├── cors.md
│   ├── authentication.md
│   ├── authorization.md
│   ├── file-upload.md
│   ├── path-traversal.md
│   ├── information-disclosure.md
│   ├── business-logic.md
│   ├── race-conditions.md
│   ├── graphql.md
│   ├── deserialization.md
│   ├── prototype-pollution.md
│   ├── request-smuggling.md
│   ├── web-cache-poisoning.md
│   ├── web-cache-deception.md
│   ├── host-header.md
│   ├── jwt.md
│   ├── oauth.md
│   ├── webhooks.md
│   ├── cloud-storage.md
│   └── reports/
│       ├── drafts/
│       └── submitted/
│
├── scope.md
├── out-of-scope.md
├── commands.md
└── README.md
```

---
### How to choose a programme

There are lots of bug bounty programs out there and choosing the correct one is crucial. This section of my methodology demonstrates the best way to do so. This is not a perfect guide for picking programmes for all skill levels and is mainly targeted at people who are just begining bug bounty and may not have as advanced skills as some hunters. This is just what I personally follow.

1. Find the bug bounty platform you want to hunt on (E.g HackerOne, BugCrowd, self-hosted etc). This differs on your skill but this guide will be tailed more towards HackerOne.
2. After you select a platform, you should always opt for programs with the least resolved reports, especially aim for low recent reports.
3. You should aviod programs with low reports and high bountys as this usually means they are very hard programs to hack.
4. Once you have filtered by reports, you should then filter by scope. Aim for the largest scope possible. On HackerOne this means filtering by wildcards.
5. You should only ever hunt on bountys that you can sign up to. Not being able to make an account reduces attack surface by a huge amount.
6. Make a list of bountys that fit these requirements and pick the best one out of them.

---

### Setup

This methodology takes place in a Linux mint environment (but will most likely work on most linux distros) and command line utils. Use each project's own documentation for installation and usage.

#### Core recon tools

| Tool | Used for | Official download or installation guide |
|---|---|---|
| Subfinder | Passive subdomain discovery | [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) |
| dnsx | DNS resolution and subdomain brute-forcing | [ProjectDiscovery dnsx](https://github.com/projectdiscovery/dnsx) |
| httpx | HTTP probing and technology fingerprinting | [ProjectDiscovery HTTPX](https://github.com/projectdiscovery/httpx) |
| Katana | Web crawling and JavaScript-aware endpoint discovery | [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana) |
| ffuf | Virtual-host and parameter discovery | [ffuf](https://github.com/ffuf/ffuf) |
| GAU | Historical URL discovery | [getallurls](https://github.com/lc/gau) |
| gf | URL-pattern filtering | [gf](https://github.com/tomnomnom/gf) |
| Nmap | Permitted network-service discovery | [Nmap download and guide](https://nmap.org/download.html) |
| Subzy | Subdomain-takeover checks | [Subzy](https://github.com/PentestPad/subzy) |

#### JavaScript and technology-recon tools

| Tool | Used for | Official download or installation guide |
|---|---|---|
| js-beautify | Beautifying JavaScript before review | [js-beautify](https://github.com/beautifier/js-beautify) |
| LinkFinder | Extracting links and endpoints from JavaScript | [LinkFinder](https://github.com/GerbenJavado/LinkFinder) |
| jq | Processing JSON and source maps | [jq downloads](https://jqlang.org/download/) |
| WhatWeb | Additional technology fingerprinting | [WhatWeb](https://github.com/urbanadventurer/WhatWeb) |
| Wappalyzer browser extension | Manual browser-side technology identification | [Wappalyzer download](https://www.wappalyzer.com/download/) |
| Burp Suite | Manual proxying and authenticated crawling | [PortSwigger Burp Suite](https://portswigger.net/burp) |

#### Cloud and runtime dependencies

| Tool | Used for | Official download or installation guide |
|---|---|---|
| cloud_enum | Cloud-storage discovery | [cloud_enum](https://github.com/initstring/cloud_enum) |
| AWS CLI | Reviewing explicitly authorised S3 buckets and objects | [AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| uv | Running cloud_enum in its Python environment | [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) |
| Python 3 | LinkFinder and cloud_enum runtime | [Python downloads](https://www.python.org/downloads/) |
| Node.js and npm | js-beautify runtime | [Node.js downloads](https://nodejs.org/en/download) |

#### Utils and wordlists

The commands `bash`, `curl`, `wget`, `grep`, `sed`, `awk`, `find`, `xargs`, `sort`, `sha256sum`, and `file` are usually available from the Linux distro's standard repositories. Install any that are missing through your distro's package manager.

`WhatWeb`, `Wappalyzer`, `Burp Suite`, `cloud_enum`, the AWS CLI, and `uv` are only needed for the methodology sections that use them. The core reconnaissance and JavaScript sections need the remaining listed tools.

---

### Useful resources
- https://github.com/danielmiessler/seclists for bruteforcing lists.
- https://portswigger.net/web-security/all-topics for docs on vulnerability information.
- https://hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html great for web explotation notes and expoitation.
- https://oreobiscuit.gitbook.io/introduction has a huge amount of bug bounty relevant information.
- https://apis.guru/graphql-voyager/ good for graphql schema visualisation.
- https://www.intigriti.com/researchers/blog good for reading about creative ways to exploit vulnerabilitys + docs for learning about niche vulnerability classes.
- https://infosecsanyam.medium.com/web-application-security-bug-bounty-methodology-reconnaissance-vulnerabilities-reporting-635073cddcf2 huge amount of writeups for complexed vulnerabilitys, worth reading.
- https://www.openbugbounty.org/bugbounty-list/ can be useful for finding niche new programs.
- https://seclists.org/fulldisclosure/ good to find the latest new vulnerabilitys explained well.
