<h1 style="text-align: center;">Web Security 101</h1>

# Summary
- [HTTPS](#https)
- [VPNs](#vpns)
- [TLS](#tls)
- [HTTP headers and cookies](#headers)
- [Attacks overview](#attacks)
- [Other resources](#resources)
- [Glossary](#glossary)

<br>

# 1. HTTPS <a id="https"></a>
## Definition
> "**HTTPS (Hypertext Transfer Protocol Secure)** is an internet communication protocol that protects the integrity and confidentiality of data between the user's computer and the site.
In HTTPS, the communication protocol is encrypted using Transport Layer Security (**TLS**) or, formerly, Secure Sockets Layer (**SSL**). The protocol is therefore also referred to as HTTP over TLS, or **HTTP over SSL**.
The principal motivations for HTTPS are authentication of the accessed website, and protection of the privacy and integrity of the exchanged data while in transit. It protects against man-in-the-middle attacks, and the bidirectional encryption of communications between a client and server protects the communications against eavesdropping and tampering. In practice, this provides a reasonable assurance that one is communicating with the intended website without interference from attackers." - [wikipedia](https://en.wikipedia.org/wiki/HTTPS)
  
HTTPS provides end-to-end encryption of traffic between the client's browser and the server.



## Use cases
* Avoid interception of messages (by someone looking at the traffic)
* Ensure integrity of data (content of the pages can not be modified before arriving to the receiver)
* Protect users privacy
* Authenticate domains (and websites running on those domains) with the help of SSL Certificate Authorities (CA) and SSL certificates
* Faster loading times than HTTP/1.1 (see [HTTP vs HTTPS](https://www.httpvshttps.com/))

HTTPS helps against script injections (cryptominers, keyloggers, ads...), DOM page modification, DNS spoofing, CSRF attacks on routers. These attacks are enabled on HTTP when one gets access to traffic (ex: at a proxy level) where they can see the traffic and inject payloads or modify the page before it reaches the user's browser. HTTPS is necessary even on static web pages, see this video: [Here's Why Your Static Website Needs HTTPS](https://www.youtube.com/watch?v=_BNIkw4Ao9w).

*Note: HTTPS does not mean you can have full trust to the website you are connecting to. It only means your connection is private. It cannot be eavesdropped and its traffic can't be modified by a man in the middle.*
> "HTTPS & SSL doesn't mean "trust this." It means "this is private." You may be having a private conversation with Satan. - [Scott Hanselman tweet](https://twitter.com/shanselman/status/187572289724887041)



## Protocol
* Encrypt data from the sender and decrypt it on the receiver's end

> TODO




## HSTS (HTTP Strict Transport Security)
* **_Strict-Transport-Security_** HTTP **response header**  
* **How it works**: a response header is returned by the server and says 'For the next X seconds (maxAge), the browser may not make an insecure request on this domain. It should be used with preloading for maximum security (if the user has never been on the website before, it will ensure it loads over HTTPS even on the first connection).
  
By default in browsers, the first request goes through HTTP if HTTPS is not mentionned, and usually the server will return a 301 Redirect to use HTTPS instead. If HSTS is set, then all the requests after the first one will ensure the use of HTTPS (until maxAge). See [RFC#6797](https://tools.ietf.org/html/rfc6797).

*i.e: strict-transport-security: max-age=31536000; includeSubDomains; preload*

Further reading: [Understanding HTTP Strict Transport Security (HSTS) and preloading it into the browser - Troy Hunt](https://www.troyhunt.com/understanding-http-strict-transport/)

> TODO Research about the 'Trust On First Use' problem (TOFU) - is the initial request being secured? Usually (without HSTS and preload), the first connection is insecure and then the connection becomes secure


## Preloading
Websites that use HSTS and the **preload option** ensure only HTTPS requests can be used between the client and the server (even if the user has never been there before, it will only be loaded over HTTPS no matter what - browser does a 307 Internal Redirect). Preloaded website lists are embedded directly in browsers binaries (see [HSTSpreload.org](https://hstspreload.org/) for submissions) and the browser itself forces the use of HTTPS from the first request. It should be used for the entire site and its subdomains.
> "However, be aware that inclusion in the preload list cannot easily be undone. Domains can be removed, but it takes months for a change to reach users with a Chrome update. Don't request inclusion for HSTS preloading unless you're sure that you can support HTTPS for your entire site and all its subdomains in the long term." - from [hstspreload.org](https://hstspreload.org/)

* **HSTS + preloading** should be considered the standard for security


## DNS over HTTPS (DoH)
> TODO Research this [wikipedia](https://fr.wikipedia.org/wiki/DNS_over_HTTPS) Option to enable in the browser (exists on Mozilla but not Chrome?)



## Further readings / Documentation to implement HTTPS

* [Mozilla guidelines on web security](https://infosec.mozilla.org/guidelines/web_security)
* [Google guidelines on web security](https://developers.google.com/web/fundamentals/security/?hl=en)
* [Does my site need HTTPS?](https://doesmysiteneedhttps.com/)
* [What is an SSL certificate? - Cloudflare](https://www.cloudflare.com/learning/ssl/what-is-an-ssl-certificate/)
* [Let's encrypt FAQ](https://letsencrypt.org/docs/faq/)
* [HTTPS is easy - a guide by Troy Hunt](https://httpsiseasy.com/) - *"Troy Hunt is a Microsoft Regional Director and MVP, web security expert known for public education and outreach on security topics" (wikipedia). He also runs a [blog (troyhunt.com)](https://www.troyhunt.com/) with knowledgeable content about web security and his [Have I Been Pwned](https://haveibeenpwned.com/) project.*
* ["What Every Developer Must Know About HTTPS"](https://www.pluralsight.com/courses/https-every-developer-must-know) : Pluralsight course on HTTPS


## Mobile apps
 **Mobile apps** do not have a browser to warn the user if the connection is using HTTPS or not. There is no certificate validatiton insurance either and no padlock to see the HTTPS status (whereas those infos are displayed in browsers). A lot of mobile apps traffic (that is not using a browser) is insecure (using HTTP, sending credentials with HTTP before getting redirected to HTTPS etc).



## CSP (Content Security Policy)
> TODO 
> 
* [Google CSP doc](https://developers.google.com/web/fundamentals/security/csp)
* [W3.org CSP2](https://www.w3.org/TR/CSP2/)
* [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* Related [X-Frames-Options](https://infosec.mozilla.org/guidelines/web_security#x-frame-options) header


<br>

# 2. VPNs (Virtual Private Networks) <a id="vpns"></a>

> TODO Research more about VPNs, how they work, good/secure ones  
> More on the value proposition of VPNs: [Troy article about the 3 Ps](https://www.troyhunt.com/padlocks-phishing-and-privacy-the-value-proposition-of-a-vpn/) aka Padlocks, Phishing and Privacy

A VPN provides encryption from your device to the VPN server. It's a way to bypass MitM attacks between your browser and the external node connecting you to the internet - in this case the VPN server. ISPs are no longer able to watch your traffic (they only see encrypted requests to a VPN IP address and the VPN hides metadata related to your request). The requests are encrypted from your browser to the VPN server and then the VPN decrypts and redirects them to the querried resources. The same happens when the resource responds to the VPN server, it is encrypted at the VPN server level and then decrypted in your browser.  

> TODO 
Does that mean that an HTTP request is still vulnerable to MitM attacks between the VPN server and the web server hosting the resource? --> Yes. Even with HTTPS (metadata becomes visible after the VPN exit node, although the payload is hidden) but it's considered a "safer segment" than the network segment between your ISP and your browser. With HTTPS enabled, the resource cannot be modified at all between the server and your browser (end-to-end encrpytion) but the ISP can see metadata related to your request (hostname, your actual ip address). ISP can also see your DNS queries which are done in plaintext and the SNI requests when you connect to an HTTPS website (bad for privacy).

**Good VPNs provide better privacy** to users (but there are also a bunch of terrible VPN providers).

VPNs **encrypt traffic** you send  
VPNs **hide your browsing habbits** (i.e. ISPs can see your traffic/metadata, DNS querries are observable, SNI - Server Name Indication leak hostnames even on HTTPS which provides access to (personal) information on people habits or the content they browse).  
VPNs can **blackhole/block bad DNS** (see the hostname you are connecting to and kill the connection if it's considered malicious thus blocking you from accessing malicious websites).  

> TODO Read about [Encrypted Server Name Indication (ESNI)](https://blog.cloudflare.com/esni/)

*i.e. NordVPN*

## Further reading on VPNs
> TODO



<br>

# 3. TLS (Transport Layer Security) <a id="tls"></a>

## TLS
>TODO



## TLS 1.2 (since 2013) vs TLS 1.3
>TODO



## 0-RTT (Zero Round Trip Time Resumption mode)
>TODO [cloudflare blog](https://blog.cloudflare.com/introducing-0-rtt/), [ssl.com article](https://www.ssl.com/faqs/network-attacks-and-security-issues/), [LDAP wiki](https://ldapwiki.com/wiki/0-RTT%20Handshakes), [another article](https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/)


## Further reading on TLS
> TODO




<br>

# 4. HTTP Headers and Cookies <a id="headers"></a>

## HTTP Request Headers
> TODO
> Host, Referer, Origin, X-Forwarded-Host
> 
> 
> 
## HTTP Response Headers

| Header | Description| Example |
|------|---|---|
| **[Strict-Transport-Security](https://developer.mozilla.org/fr/docs/S%C3%A9curit%C3%A9/HTTP_Strict_Transport_Security)** | Enable HSTS (and preload) | Strict-Transport-Security: max-age=31536000; includeSubDomains; preload|
| **[Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)** | Control resources the user-agent is allowed to load (helps against XSS attacks). Specify allowed server origins and script endpoints|Content-Security-Policy: default-src 'self'; img-src 'self' https://i.imgur.com; object-src 'none'; **upgrade-insecure-requests**|
|**[X-Frames-Options](https://infosec.mozilla.org/guidelines/web_security#x-frame-options)**|Control how your site may be framed within an iframe (and avoid clickjacking attacks)|X-Frame-Options: DENY|
| **[X-Content-Type-Options](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options)** | Prevents browsers from MIME-sniffing away from the declared Content-Type | X-Content-Type-Options: nosniff|

## Cookies
### HTTP Only
An HTTP Only cookie can't be read by a clientside script. So if an attacker gets an XSS on the page, it can't access this cookie.
> TODO Defense against XSS attacks from other domains accessing the cookies? Research this

### Secure
Ensures that the cookie will never be sent over an insecure connection (HTTP request) --> always sent with HTTPS. Avoids MitM attacks intercepting this value.
> TODO

### SameSite
SameSite is a cookie attribute (from the Set-Cookie response header) which aims to mitigate CSRF attacks (can [sometimes](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1) be bypassed). It helps the browser decide whether to send cookies along with cross-site requests. Possible values for this attribute are :

* **Lax** : send the cookie except on certain CSRF-prone request methods such as POST/PUT - only send for top-level navigation (such as clicking a link, requests made by JavaScript do not include the cookie) using safe HTTP methods ex: GET, HEAD, OPTIONS. *(default value for cookies in Chrome since Feb. 2020)*
*  **Strict** : never send the cookie from a cross-site context, ex: when clicking on a link from an external website

* **None** : always send the cookie *(cookies set as SameSite None require the Secure attribute in Chrome)*

> Set-Cookie: JSESSIONID=xxxxx; SameSite=Strict  
> Set-Cookie: JSESSIONID=xxxxx; SameSite=Lax

Limitations: 

- if a website uses a GET method to perform a state update action (ex: changing password or email) then it can be abused as it does not do anything on GET requests.  
- some frameworks are tolerant to different HTTP methods, a request could be accepted as a GET request even if it will be resolved by design using the POST request route/controller (thus bypassing the SameSite cookie attribute)


### More on SameSite:
- [OWASP CSRF Prevention - SameSite cookie attribute](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute)
- [IETF definition of SameSite cookie attribute](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1)
- [PortSwigger - Defending against CSRF with SameSite cookies](https://portswigger.net/web-security/csrf/samesite-cookies)

## Further reading on HTTP headers and cookies
> TODO



<br>

# 5. Attacks overview <a id="attacks"></a>

## Clickjacking attacks
> TODO [OWASP Defense CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), ...


## SSL stripping
 **MITM attack** where the attacker communicates with the client over HTTP and relays the requests to the server over HTTP (or HTTPS if the server does not allow HTTP). That way the attacker sees all the client's traffic over HTTP. (Connection is 'stripped' of SSL and downgraded to HTTP).


## XSS (Cross-Site Scripting)
> TODO

A XSS is a technique to execute your own javascript on the domain of an application.
### XSS Cheat Sheets
- [PortSwigger - XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP - XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

### Stored XSS
The payload is sent to a database and is stored there and is called every time a user visits the page where its resource is loaded (ex: sending a XSS payload through a form input which value is later embedded on the page without being sanitized properly).

Note: *Blind XSS* are a type of stored XSS where you don't have access to the page that triggers the XSS (admin panels, ...) --> [XSS hunter](https://xsshunter.com/) tool to help find blind XSS?

### Generic XSS

### DOM based XSS
DOM based XSS exploit the DOM (DOM: how a document is represented in the browser) with objects containing metadata from the DOM such as **document**, **window**, ...
Ex: document.location, window.location.search (search terms), ...

For example if an app is using jQuery and selecting based on the url retrieved from the document object and then outputting the element in the page. If you can manipulate the location retrieved, a crafted payload can execute the XSS when jQuery tries to select the element in the DOM.

```typescript
const url = document.location.toString();
$('some jQuery selector '+url.split('#')[1]+'...').tab.show() // vulnerable to DOM based XSS
```

- [PortSwigger - DOM based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [OWASP - DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

### Reflected XSS
The XSS payload input is not stored in a database but reflected on some other page. Using malicious links you could send to users, you could execute a payload on the users page.

## CSRF (Cross-Site Request Forgery)
### Definition
CSRF is a type of attack to make people send unintentionnal requests to a target domain (on which they are logged in and can perform specific actions - ex: change their password).

Attackers can execute **forged requests** (trick the browser to issue an authenticated request to the server without the logged in user knowing) by using the user's **auth cookie**. Usually a CSRF attack is done when a user is visiting a malicious page (or a page embedding a malicious ad) that sends a request to a website they are currently logged in and takes advantage of their auth cookie to perform an authenticated action. The malicious page only has to replicate the original request (same url, payload, method) and the auth cookie will be sent automatically by the browser. Typically, the form+submit action can be stored in a hidden \<iframe> and the user won't notice anything when visiting the malicious page.

What does a CSRF request look like? It is the same as the actual request to perform the action: request URL + request method + payload (+auth cookie). **An auth cookie is sent with each request after you have logged in** (which lets the server know who you are). **Cookies are automatically sent by the browser with each request for the domain (if not expired)**.

CSRF happens because the request is predictable (url, method, data). In order to protect an action, you need to add unpredictability (aka **CSRF token/anti-forgery token**) and validate it on the server.

### Token-based CSRF mitigation
Different patterns using a CSRF token can be used to mitigate CSRF attacks, according to the OWASP cheat sheet : 

- [Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern) - requires to maintain a list of valid issued tokens on the server (state)
- [Encryption Based Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#encryption-based-token-pattern) - does not need to maintain a list of tokens on the server (stateless pattern)
- [HMAC Based Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#hmac-based-token-pattern) - does not require to maintain a list of tokens on the server, and less computation (hash instead of encrypt/decrypt)

### [Double Submit cookie method](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie)
Use this method if maintaining a CSRF token list on the server is problematic. Generate the CSRF token and store it as a cookie on the client and ensure that any request performed also sends the token value in the request payload. Compare on the server that the request token and the cookie token match. *This method only works on HTTPS connection* otherwise the cookie can be seen and sent by modifying the request payload. To enhance the security of this method, the token can be stored in an **encrypted cookie** and decrypted on the server (so the value of the token can't be seen in the cookies). It is also possible to use an **HMAC representation of the token** to hide its value in the client cookie and validate the hash server side (less computing than encrpytion).



### A CSRF protection method explained in Troy Hunt's [CSRF video](https://www.youtube.com/watch?v=hW2ONyxAySY)

This method uses 2 paired tokens: **1 CSRF cookie token** (server side encrypted cookie or HMAC generated token representing the user session and an expiry date) + **1 generated CSRF token** (token paired with the cookie and generated by the server with cryptography using a private key known only by the server) embedded on the web page (in a hidden form field, a HTML meta tag).


- **set a CSRF token in the cookies** of the logged in user (generated by the server and separate from the user's auth cookie)
- **set an anti-forgery token in the DOM page/HTML form** that will perform the request (generated by the server using cryptography and the user CSRF cookie)
- on the server, **link the cookie with the user id** to know which cookie is valid for which user
- on the server, **validate the cookie** sent by the user (is it their own cookie?) **and the anti-forgery token** (is it a valid generated token for this cookie?) before performing the action


If an attacker wants to perform the same attack on a website implementing the above mentioned CSRF protection, he has to set a valid CSRF token in the form field (which is generated and hard/impossible to guess) that also matches the CSRF token in the cookie of the user's browser. **In order to bypass this protection, they have to find a XSS to set their own form field token and cookie in the browser of the user before the request**. But if the cookie is linked to the registered user on the server and validated before performing the action, then the attacker will be blocked because the server will recognize that this cookie+generated token do not belong to the logged in user. Finally, the CSRF cookie should be **HttpOnly** and **Secure** to ensure that it can't be read from the clientside JavaScript and that it can never be sent over an HTTP (unsecured) connection (to avoid XSS / MitM attacks retrieving the users auth cookie & valid generated token).

*Should the token be valid only once and regenerated on each page load?*  
No, the cookie token should be shared for all rendered pages on the same browser session. That way the user can have multiple tabs rendering the application and send requests from all of them. Otherwise, the cookie would be overwritten by the last opened tab and block other tabs from sending valid requests (or block when the user hit the back button and tries to submit the same request). The generated CSRF token should be unique per session (even though a per-request unique token would be more secure). See **[OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)**

*What if a state changing request is using the GET request method?* - from [PortSwigger](https://portswigger.net/web-security/csrf) 
> CSRF exploits using the GET method can be fully self-contained with a single URL on the vulnerable web site or they can directly be fed to victims with a malicious URL on the vulnerable domain. A self-contained attack would look like this: `<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">`

This should be avoided when developping the application. The **POST, PUT, PATCH, and DELETE methods should have a CSRF token** attached to the request. And the safe methods GET, HEAD, OPTIONS, TRACE should not be state changing requests.

### Double submit token protection limitation - from [PortSwigger](https://portswigger.net/web-security/csrf)

The double submit cookie is simple to implement but possible to bypass if the attacker manages to set a cookie in the victim's browser (if there is no other server side validation apart from verifying 'csrf param === CSRF cookie value').
> Sometimes, the website only stores the CSRF token clientside and does not maintain a list of valid issued tokens on the server. It only generates a CSRF token clientside and requires at validation that the csrf param in the request has the same value as the CSRF cookie. This is sometimes called the "double submit" defense against CSRF, and is advocated because it is simple to implement and avoids the need for any server-side state. The attacker can perform a CSRF attack if the website contains any cookie setting functionality. He does not need to obtain a valid token but simply invent a token (perhaps in the required format, if that is being checked), leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

### Other mitigation techniques:

- **Referer request header** and strict Referer policy on login pages (see [Robust Defenses for Cross-Site Request Forgery paper](https://seclab.stanford.edu/websec/csrf/csrf.pdf))
- Use of **custom request headers** especially on AJAX/XHR calls: "this defense relies on the same-origin policy (SOP) restriction that only JavaScript can be used to add a custom header, and only within its origin. By default, browsers do not allow JavaScript to make cross origin requests with custom headers." - [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers)
- User based interaction (re-authentication via password or stronger like 2FA, one-time tokens, CAPTCHA) for specific requests that need strong CSRF protection (transfering funds, modifying a password...)

*Note 1: Many frameworks have __built-in CSRF protection__. Avoid re-implementing it yourself...*  
*Note 2: XSRF is the same acronym as CSRF*

### More on CSRF:
* [Understanding CSRF](https://www.youtube.com/watch?v=hW2ONyxAySY) - a tutorial video by Troy Hunt
* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) - OWASP guidelines
* [PortSwigger CSRF](https://portswigger.net/web-security/csrf) - article & labs
* [Defending against CSRF with SameSite cookies](https://portswigger.net/web-security/csrf/samesite-cookies) - PortSwigger article
* [Common CSRF prevention misconceptions](https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2017/september/common-csrf-prevention-misconceptions/)
* [Robust Defenses for Cross-Site Request Forgery](https://seclab.stanford.edu/websec/csrf/csrf.pdf) research paper


## SSRF (Server-Side Request Forgery)
> TODO

## SQLI (SQL Injection)
> TODO

## Path traversal
> TODO

## LFI (Local File Inclusion)
> TODO

## DDoS (Distributed Denial of Service)
> TODO

## Information Leakage
> TODO

## Credentials stuffing
> TODO

## RCE (Remote Code Execution)
> TODO

## Bruteforce attacks
> TODO

## Server-Side Template Injection
> TODO

## OS Commanding (command injections)
> TODO

## HTTP Response splitting (CRLF injections)
> TODO

## Web cache poisoning
> TODO

## Prototype Pollution
> TODO

## URL redirection abuse
> TODO Usually for phishing attacks [OWASP Unvalidated Redirects & Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), [CWE Mitre](https://cwe.mitre.org/data/definitions/601.html) ...

## Abuse of Functionality
> TODO [WASC link](http://projects.webappsec.org/w/page/13246913/Abuse%20of%20Functionality)  abuse of an application's intended functionality to perform an undesirable outcome ex: password recovery flows, send mails functions, abusing functionality to make unrestricted proxy requests...

## URL/SSL/TLS Spoofing
> TODO [wiki](https://fr.wikipedia.org/wiki/Spoofing)

## ARP spoofing (aka ARP poisoning)
> TODO [wiki](https://fr.wikipedia.org/wiki/ARP_poisoning)

## XML External Entity (XXE) Processing

## WAF Bypass

## IDOR (Insecure Direct Object Reference)

## 


<br>

# 6. Other resources <a id="resources"></a>

## Documentation
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [Mozilla Web Security](https://infosec.mozilla.org/guidelines/web_security)
* [Google Web Security](https://developers.google.com/web/fundamentals/security/?hl=en)
* 


## Blogs / Articles
* [Troy Hunt Blog](https://www.troyhunt.com/)
* [What Every Developer Must Know About HTTPS](https://www.pluralsight.com/courses/https-every-developer-must-know) (3h30min course on Pluralsight)
* [Here's Why Your Static Website Needs HTTPS](https://www.troyhunt.com/heres-why-your-static-website-needs-https/)
* [Web App attacks 2019](https://www.ptsecurity.com/ww-en/analytics/web-application-attacks-2019/)
* [We didn't encrypt your password, we hashed it. Here's what that means](https://www.troyhunt.com/we-didnt-encrypt-your-password-we-hashed-it-heres-what-that-means/)



<br>

# 7. Glossary <a id="glossary"></a>

A few acronyms I keep on forgetting, that might also be useful to others...

|Acronym|Description|
|---|---|
|ARP|Address Resolution Protocol|
|CORS|Cross-Origin Resource Sharing|
|CSP|Content Security Policy|
|CSRF|Cross-Site Request Forgery|
|IDOR|Insecure Direct Object Reference|
|PII|Personally Identifiable Information|
|SSL|Secure Sockets Layer|
|TLS|Transport Layer Security|
|WAF|Web Application Firewall|
|XXE|XML External Entity|