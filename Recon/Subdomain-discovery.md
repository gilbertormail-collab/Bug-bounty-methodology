# Wide subdomain enumeration

### Key Concepts

The goal of wide subdomain enumeration is the discover as many attack surfaces as possible, esspecially hidden subdomains. We are looking for exposed development
subdomains, exposed staging subdomains and other relevant subdomains that we can test. The goal is to have as many options as possible.

---
### File structure

The file structure should be as follows:
```
target.com/
│
├── recon/
│   │
│   ├── automatic-recon/
│   │   │
│   │   ├── notes.md
│   │   ├── domains.txt
│   │   ├── live.txt
│   │   ├── live_with_info.txt
│   │   ├── ffuf_vhosts.txt
│   │   ├── dorks.txt
│   │   ├── endpoints/
│   │   │  ├── endpoints.txt
│   │   │  └── params.txt
│   │   ├── javascript/
│   │   │  ├── js-files.txt
│   │   │  ├── endpoints.txt
│   │   │  └── secrets.txt
│   │   └── vulnerability_scans/
│   │       ├── subdomains_scan.md
│   │       ├── vulnerability_type_domains.txt
│   │       ├── subdomain_takeover_scan.txt
│   │       └── nmap_scan.txt
│   │
│   └── manual-recon/
│       │
│       ├── notes.md
│       ├── interesting-endpoints.md
│       └── interesting_subdomain_name/
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

### Steps for enumerating subdomains
This will focus on enumerating as much attack surface as possible.

1. Run `subfinder` to find a majority of subdomains. 
    Commands:
    - `subfinder -d target.com -all > domains.txt`

2. Next run`dnsx` to bruteforce any more domains through dns bruteforcing. This step is required as some domains may not be found by subfinder if they are not in Certificate transparency logs. 
    Commands:
    - `dnsx -d target.com -w /home/g/Hacking/hacking-map/Bug bounty methodology/Recon/namelist.txt -asn -cdn -all > dns_bruteforce_domains.txt`
3. After this, go to the website https://subdomainfinder.c99.nl/ and download the list of subdomains for your target.
4. Next is to enumerate as many vhosts (virtual hosts) as possible
    Commands:
    - `ffuf -u target.com -H "Host: FUZZ.example.com -w /home/g/Hacking/hacking-map/Bug bounty methodology/Recon/subdomains-top1million-110000.txt"` 
    - Run for a little bit and then filter by the size of the requests with `-fs size` to get valid ones then append ` > ffuf_vhosts.txt` to main command.

5. Use google and other search engines operators to find relevant information on the company. Save any relevant info to the file `dorks.txt`.
    Tools:
    -  https://pentest-tools.com/information-gathering/google-hacking for premade google dorks.
    - Refer to https://ahrefs.com/blog/google-advanced-search-operators/ for any other relevant google search operators.


6. Run `httpx` on all current subdomains to discover which ones are live and to get some other useful information about them. 
    Commands:
    - `httpx -l domains.txt -sc -ip -tech-detect > live_with_info.txt`
    - `httpx -l domains.txt > live.txt`

7. Next run `katana` to gather as many endpoints as possible on subdomains.
    Commands:
    - `katana -list live.txt -d 3 -kf all -H X-Bug-Bounty:HackerOne-ddddddawd -fs rdn > endpoints.txt`
    - Use `katana -list live.txt -d 3 -kf all -headless > endpoints.txt` if pages dont render until javascript does.

8. Run nmap on all subdomains to scan for vulnerable services.
    Commands: 
    - `nmap -iL live.txt -sV --open -sC -T4 > nmap_scan.txt`

9. Enumerate as many parameters as possible.
    Commands:
    - `grep "=" endpoints.txt > params.txt`
    - `gau target.com | grep "=" > params.txt`

10. Do automatic vulnerability testing, looking for low hanging fruit bugs. Check for all 
    Commands:
    - `sif -f live.txt -dnslist small -dork -git -js -cms -headers -sh -cms -c3 -st -sql -lfi -jwt -openapi -cors -redirect -xss -framework -md subdomains_scan.md -H X-Bug-Bounty:HackerOne-ddddddawd`
    - `subzy run --targets live.txt > subdomain_takeover_scan.txt`
    - `gau --subs target.com | gf vulnerability_type > vulnerability_type_domains.txt`
    - `gf vulnerability_type live.txt && gf vulnerabilit_type endpoints.txt`
11. Organise all data to a couple central files. Make sure there is 1 file for params, endpoints, scan results and any other info.
    Commands: 
    - `cat file1.txt file2.txt | sort -u > merged.txt` Merges 2 files and removes dupes.
12. Identify high interest subdomains. Any subdomains with an interesting scan results or name, save to a file of interesting subdomains.
 
---

### Deep subdomain enumeration
This will focus on enumerating as many values as possible from individual subdomains instead of dicovery in mass.

1. Gather all information from wide scans of this subdomain into 1 file.
    Commands:
    - `grep "sub.target.com" endpoints.txt`
    - `grep "sub.target.com" params.txt`
    - `grep "sub.target.com" live_with_info.txt`
    - `grep "sub.target.com" ffuf_vhosts.txt`
    - `grep "sub.target.com" dorks.txt`
    - `grep "sub.target.com" nmap_scan.txt`
    - `grep "sub.target.com" subdomains_scan.md`
    - `grep "sub.target.com" subdomain_takeover_scan.txt`
    - `grep "sub.target.com" vulnerability_types_files.txt`

2. Vist the domain and use the wapplyzer extention to discover information about the sites tech stack and save it to the information file.
3. 




---

## draft below
### Interesting subdomain enumeration:
- Keep a separate file for each interesting subdomain with its specific info in it.
- Make a list of interesting subdomains regarding name, content or services running on them. Use grep with commonly interesting keywords if the list is large such as admin, api, prod, dev, etc.
- Use the browser extension wappalyzer to get more information on the websites tech stack on any interesting subdomains
- Use httpx to analyze the services running on them further with `httpx -d target.com -title -tech-detect -status-code -follow-redirects -web-server -ip -cdn -asn` then use katana to gather even more endpoints with the command `katana -u target.com -d 8 -headless -js-crawl -jsluice -kf all` save both these results to a file.
- Run burpSuite crawler on the interesting subdomains and save endpoints to a file.
- Go to the directory `/Hacking/tools/cloud_enum` and run `uv run python cloud_enum.py -k company_name` to search for publicly exposed cloud infrastructure.
- Any exposed aws buckets use the command `aws s3 ls s3://bucket_name --no-sign-request --recursive` to list the content and do `aws s3 cp s3://bucket_name/path --no-sign-request` to list the content of a file.
- Go to https://pentest-tools.com/information-gathering/google-hacking and use all templates on any interesting subdomains and save any useful results. Refer to https://ahrefs.com/blog/google-advanced-search-operators/ for any other relevant google search operators.
- Enumerate more parameters with ffuf using `ffuf -u target.com/page?FUZZ=test -w params.txt` and merge with current parameters list for that subdomain.
- For api parameter fuzzing use `ffuf -u https://target.com/api -X POST -H "Content-Type: application/json" -d '{"FUZZ":"test"}' -w params.txt` and merge the results with current parameters list.


### JS beautifying on subdomains:
- Get all found .js files from the endpoints.txt files by doing `grep -E "\.js($|\?)" endpoints.txt > js-files.txt`. 
- Also do `curl -s https://target.com | grep -oE 'src="[^"]+\.js[^"]*"' > js-files.txt` to get more js files.
- beutify specific js files using `curl -S https://target.com/file.js  | js-beautify > beautified.js grep -iE "(api.?key|secret|password|token|credential|auth)" beautified.js` to search for secrets. Use grep to search for other context specific keywords.
- To beautify and download all javascript files, use `wget -i js-files.txt` and then beautify them as you need to.
- Use these searches on all beautified files:
	`grep -RniE "token|jwt|bearer|authorization|oauth|refresh" beautified/`
	`grep -RniE "secret|apikey|api_key|password|private|key" beautified/`
	`grep -RniE "admin|dashboard|manage|internal" beautified/`
	`grep -RniE "debug|test|dev|staging|sandbox" beautified/`
  and any other relevant searches.
- Use linkfinder to find more endpoints by going to `/Hacking/tools/LinkFinder` then doing `source venv/bin/activate` then `python linkfinder.py -i target.com/jsfile.js > linkfinder.txt` and merge results with endpoints.txt