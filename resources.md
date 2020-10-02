# Resources


## Documentation

| Resource | Description |
|---|---|
|[OWASP Top Ten 2017](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/)|Documentation about web app security (covers top 10 most common vulns, provides great examples, guidelines, tools and other references to read)|
|[OWASP XSS filter evasion cheatsheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)||
|[PortSwigger XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-sandbox-escapes-reflected)|An up to date XSS cheat sheet by the creators of the Burp Suite|
|[GitLab's RedTeam Tech Notes](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/red-team-tech-notes)|Articles, tools, talks shared by GitLab's RedTeam|
|[GitLab's RedTeam GKE-K8S attacks](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/red-team-tech-notes/-/blob/master/K8s-GKE-attack-notes/README.md)|A huge guide on the GKE architecture, GKE recon, and attack scenarios |
|[GitLab Security Practices](https://about.gitlab.com/handbook/security/#what-to-do-if-you-suspect-an-email-is-a-phishing-attack)|GitLab Security Guidelines for employees and a good read/reminder on Phishing Attacks|
|[PortSwigger' Web Security Academy](https://portswigger.net/web-security)|Free online web security training course (labs)|

## Random articles
This section lists various resources on the following topics: web application security, bug bounty stories, disclosed vulnerabilities, web security research, ...

|Resource|TL;DR;|Something I learnt|
|---|---|---|
|[Phishing attack on Office 365](https://threatpost.com/office-365-phishing-attack-leverages-real-time-active-directory-validation/159188/)|Attackers checking AD credentials via API in real time as the victim enters its credentials on the fake landing page|Phishing attacks are more likely to work when sent on a Friday evening with an important/worrying title (victim is tired, pays less attention, more prone to click)|
[Here is why you need HTTPS even on a static website](https://www.troyhunt.com/heres-why-your-static-website-needs-https/) and associated [video](https://www.youtube.com/watch?v=_BNIkw4Ao9w&feature=emb_logo)|HTTPS always necessary to ensure integrity of page (no scripts injected, no content modified)|Any content can be injected (keylogger, cryptominer, ads, CSRF attacks on routers, DDoS attacks, DOM modification) if the request is over HTTP and you have a MitM (ex: on a WiFi)|
|[Value proposition of VPNs](https://www.troyhunt.com/padlocks-phishing-and-privacy-the-value-proposition-of-a-vpn/)|Avoid phishing attacks, better privacy and ISP can't watch metadata, also protects you on HTTP calls/badly implemented TLS websites (browser <--> exit node of VPN segment tunnel encrypted)|Metadata seen by ISPs (domain via Server Name Indication) - DNS requests are made in plaintext - 2% of Top 1million sites use HSTS+preloading|
|[Grafana+HIBP to detect credential stuffing attacks](https://stebet.net/using-hibp-appinsights-grafana-to-detect-credential-stuffing/)|Grafana charts to detect credential stuffing attacks in real-time using a metric which utilizes HIBP Password API, 2FA challenges, and failed auth login attempts|Interesting thought process to build this 'High-Risk Activity' metric and use a tool to mitigate false positives (on normal user activity 'noise')|
|[Security by obscurity](https://utkusen.com/blog/security-by-obscurity-is-underrated.html)|Avoid using default ports to run your apps so if they get scanned, they are less likely to be discovered. Also, obfuscate source code, minify JS code|\[0-65535\] is the port range, ssh port 22, *Risk = Likelihood x Impact*|
|[ZeroLogon vulnerability](https://www.secura.com/blog/zero-logon), [PDF](https://www.secura.com/pathtoimg.php?id=2055)|How a security researcher found a vulnerability in Microsoft’s Netlogon authentication process and managed to take over Windows AD domains (escalate to admin privileges on Domain Controller by setting the password of an admin to a blank string) - Unauthentified Admin priviledges escallation|Interesting explanation on how AES-CFB8 encryption is done with a random key generated and chained XOR operations between bytes of the cyphertext and bytes of the key|
|[Nmap legal issues](https://nmap.org/book/legal-issues.html)|Reminder on what Nmap can do and how it's supposed to be used with the aggreement of the targeted domain. The law where the server is located applies and each country has its own legislation (on what is allowed and what can get you in trouble).|"Remember that many states have their own computer abuse laws, some of which can arguably make even pinging a remote machine without authorization illegal"|
|[Hakluke's guide to Nmap](https://medium.com/@hakluke/haklukes-guide-to-nmap-port-scanning-is-just-the-beginning-25d971692fdb)|Great guide on some basic usage of Nmap (port scanning and more)| - A bunch of commands - |
|[Axiom guide](https://adamsvoboda.net/axiom-feels-like-cheating/amp/?__twitter_impression=true)|Getting started with Axiom (tool by @pry0cc to launch multiple cloud instances, start distributed tasks, and much more). Also check out [Axiom's repo](https://github.com/pry0cc/axiom) with recent doc update|Cool tool and discovery of what recon is and how it is automated for bug bounties|
|[Bug Bounty Story on a Bus Ticketing app](https://medium.com/bugbountywriteup/how-i-hacked-redbus-an-online-bus-ticketing-application-24ef5bb083cd)|Local File Inclusion (arbitrary file read) thanks to a 3rd party plugin (PDF generator) that escalated into a PII leakage using the API|Interesting payload *\<pd4ml:attachment src=”file:///etc/passwd”>* and escalation from there. Exploit made possible by carefully reading the 3rd party module's documentation|
|[Aircrack-ng WiFi deauth attack](https://medium.com/bugbountywriteup/your-neighbours-music-sucks-aircrack-ng-for-the-rescue-a5124a2e2734)|How a deauthentication attack can easily be performed to force a device off a WiFi| - |
|[Portswigger XSS Article](https://portswigger.net/research/redefining-impossible-xss-without-arbitrary-javascript)|XSS made possible inside a single quote string with a limited charset [a-zA-Z0-9’+.`]|- TO READ AGAIN (not so easy)|
|[TikTok vuln (fake videos)](https://www.mysk.blog/2020/04/13/tiktok-vulnerability-enables-hackers-to-show-users-fake-videos/)|TikTok vulnerability using insecure HTTP calls to retrieve videos from a CDN. PoC on how to display fake videos using a compromised DNS server (pointing to a corrupted DNS record with a fake server) allowing to modify the content of resources shown to the user|Yet another example of HTTP content modification (this time from a DNS record modification to mimick an official CDN with an evil server)|
|[We didn't encrypt your password, we hashed it](https://www.troyhunt.com/we-didnt-encrypt-your-password-we-hashed-it-heres-what-that-means/)|Difference between hashing and encryption - Why salted hashes are mandatory - Why leaking hash is still an issue (bad passwords can be cracked)|Password hash for non-IT people: "A password hash is a representation of your password that can't be reversed, but the original password may still be determined if someone hashes it again and gets the same result."|
|[Understanding HSTS and preload](https://www.troyhunt.com/understanding-http-strict-transport/)|Strict-Transport-Security response header with max-age - HSTS is used to ensure any page in the domain is forced to be served via HTTPS for max-age duration - Preload option to ensure first connection is not made via HTTP by default (with a redirect to HTTPS) but directly through HTTPS (can't be bypassed because it's embedded in browsers)|HSTS with preload creates 307 Internal redirect - |
|[Abusing the Docker API](https://www.hackingarticles.in/docker-for-pentester-abusing-docker-api/)|Explains how Docker API can be exposed on a machine running Docker - you can remotely execute docker commands (by connecting with your docker demon) - you can connect to docker containers (possible container highjacking/container escape attack)|Docker API is a thing - Port 2375/tcp used|

## Videos | Courses

|Resource|TL;DR;|Something I learnt|
|---|---|---|
|[JS Prototype Pollution (Part 2)](https://www.youtube.com/watch?v=yDmOXhr8wmw), [Part1](https://www.youtube.com/watch?v=J3MIOIqvV8w) | Great video explaining prototype pollution, and how it can be used to perform attacks (data leaks, XSS)|Prototype pollution comes from overriding \_\_proto__ property that all JS objects inherit and that can be copied by error from third-party libraries using merge/copy functions of objects (or during deserialization) It can be used to add any property to a class of objects (or all) - Also learnt about properties being retrieved by chains (from current object to 'parent classes') by looking at constructors|
|[Understanding CSRF - tutorial](https://www.youtube.com/watch?v=hW2ONyxAySY)| TO WATCH|-|
|[HTTPS crash course](https://www.pluralsight.com/courses/https-every-developer-must-know)|TO WATCH|-|


## Others
|Resource|Description|
|---|---|
|[HTTPS is easy](https://httpsiseasy.com/) | Guide on how to easily setup HTTPS for free with HSTS and preload config|
|[XSS Game](https://xss.pwnfunction.com/)| Some XSS challenges with solution & explanation|
	