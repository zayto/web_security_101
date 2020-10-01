# Tools related to web security / bug hunting
Just a quick overview of a few tools I have seen mentioned in my readings that seemed interesting.

## Burp
[Burp](https://portswigger.net/burp) is a **proxy** (watching the traffic on your browser) which lets you \[**send**/**edit**/**intercept**\] HTTP requests. Burp is an IDE with many features (community edition and entreprise edition).
Alternative: [OWASP ZAP](https://www.zaproxy.org/) (ZAP Proxy)

* Repeater (repeat requests)
* Intercept (intercept requests before they happen)
* Intruder (bruteforcing tool)


## Axiom
[https://github.com/pry0cc/axiom](https://github.com/pry0cc/axiom) : an awesome tool made by [@pry0cc](https://twitter.com/pry0cc) to easily launch & setup cloud instances (VPS), install tools and run distributed work on those for recon/pentesting/bug hunting.
[Axiom: It Kinda Feels Like Cheating - Adam Svoboda](https://adamsvoboda.net/axiom-feels-like-cheating/amp/?__twitter_impression=true) - a good article on how to get started with axiom, the endless possibilities of the tool (modules) and how to use it in bug hunting.

## Nuclei
[https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) : "Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use"


## LazyRecon
[https://github.com/nahamsec/lazyrecon](https://github.com/nahamsec/lazyrecon) : "LazyRecon is a script written in Bash, it is intended to automate some tedious tasks of reconnaissance and information gathering. This tool allows you to gather some information that should help you identify what to do next and where to look."


## SecLists
[https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) : "a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more."

## XSS Cheat Sheets
[PortSwigger's Cross-site scripting cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
[OWASP XSS Filter evasion cheat sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

## Token-Hunter
[Token-Hunter](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/token-hunter) : a project made by GitLab Red Team to "Inspect GitLab assets like snippets, issues, and comments/discussions for sensitive information like GitLab Personal Access Tokens, AWS Auth Tokens, Google API Keys, and much more."

## GitRob
[GitRob](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gitrob) : "forked repository that adds several features to gitrob including GitLab support, commit content searching, in-memory repository cloning, and more."
"Gitrob is a tool to help find potentially sensitive information pushed to repositories on GitLab or Github. (looking at commit history and flag files and/or commit content that match signatures for potentially sensitive information)"

## Go-dork
[https://github.com/dwisiswant0/go-dork](https://github.com/dwisiswant0/go-dork) : a dork scanner written in Go to utilize search engines (Google, Shodan, Bing, Duck, Yahoo and Ask)

## uDork
[https://github.com/m3n0sd0n4ld/uDork](https://github.com/m3n0sd0n4ld/uDork) : a script that uses advanced Google search techniques to obtain sensitive information in files or directories, find IoT devices, detect versions of web applications, and so on.

uDork does NOT make attacks against any server, it only uses predefined dorks and/or official lists from exploit-db.com (Google Hacking Database: https://www.exploit-db.com/google-hacking-database).

## FFUF (fuzzer)
[https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) : a web fuzzer written in Go

## NoSQLi
[https://github.com/Charlie-belmer/nosqli](https://github.com/Charlie-belmer/nosqli) : NoSQL injection CLI tool

## XSS-Payloads
[https://github.com/RenwaX23/XSS-Payloads](https://github.com/RenwaX23/XSS-Payloads) : a list of XSS vectors/payloads maintained by [@RenwaX23](https://twitter.com/RenwaX23) that can be used to bypass WAF and find XSS vulnerabilities

## Nmap
[Nmap](https://nmap.org/) : a port scanner tool and much more ("Nmap - *Network Mapper* - is a free and open source utility for network discovery and security auditing)
A good read on [Legal Issues (related to Nmap usage)](https://nmap.org/book/legal-issues.html)
See [Hakluke's guide to Nmap port scanning](https://medium.com/@hakluke/haklukes-guide-to-nmap-port-scanning-is-just-the-beginning-25d971692fdb)


## WebHackersWeapons
[https://github.com/hahwul/WebHackersWeapons](https://github.com/hahwul/WebHackersWeapons) : a project documenting a list of web hacking tools useful for bug hunting with a CLI interface to easily install them.