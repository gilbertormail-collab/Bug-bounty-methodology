

Useful command `cat file1.txt file2.txt | sort -u > merged.txt` merges 2 files and removes duplicates.
X-Bug-Bounty: HackerOne-ddddddawd
### Wide subdomain enumeration:
- Run subfinder on the target with the command `subfinder -d target.com -all > domains.txt`, then httpx to analyze services and status codes with the command `httpx -l domains.txt -sc -ip -tech-detect > live_with_info.txt` and save a list of live subdomains. Also do `httpx -l domains.txt > live.txt` to get a list of just live domains.
- Use katana to scan all live domains with the command `katana -list live.txt -d 3 -kf all -H X-Bug-Bounty:HackerOne-ddddddawd -fs rdn > endpoints.txt` and `katana -list live.txt -d 3 -kf all -headless > endpoints.txt` if the page only renders after javascript executes.
- Scan all live subdomains with sif with the command `sif -f live.txt -dnslist small -dork -git -js -cms -headers -sh -cms -c3 -st -sql -lfi -jwt -openapi -cors -redirect -xss -framework > subdomains_scan.txt` and save any positive flags and save the entire scan to a folder for later use.
- Scan all subdomains with nmap using `nmap target.com -sV`. 
- Find all parameters katana found with `grep "=" endpoints.txt > params.txt`.
- Run `gau target.com | grep "="` to find more parameters and merge them into `params.txt`.
- Run `gau --subs target.com | gf vulnerability_type > vulnerability_type_domains.txt` and `gf vulnerability_type live.txt && gf vulnerabilit_type endpoints.txt` to see which domains may be worth testing for which vulnerability's.
- Check for subdomain takeover with `subzy run --targets live.txt` 

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