<h1 style="text-align: center;">Web Security 101</h1>

# Summary
1. [HTTPS](#https)
- [TLS](#tls)
- [Content Security Policies](#csp)
- [HTTP headers and cookies](#headers)
- [Attacks overview](#attacks)
- [Miscellaneous](#misc)
- [Other resources](#resources)
- [Glossary](#glossary)

<br>

# 1. HTTPS <a id="https"></a>
## Definition
> "**HTTPS (Hypertext Transfer Protocol Secure)** is an internet communication protocol that protects the integrity and confidentiality of data between the user's computer and the site.
In HTTPS, the communication protocol is encrypted using Transport Layer Security (**TLS**) or, formerly, Secure Sockets Layer (**SSL**). The protocol is therefore also referred to as HTTP over TLS, or **HTTP over SSL**.
The principal motivations for HTTPS are authentication of the accessed website, and protection of the privacy and integrity of the exchanged data while in transit. It protects against man-in-the-middle attacks, and the bidirectional encryption of communications between a client and server protects the communications against eavesdropping and tampering. In practice, this provides a reasonable assurance that one is communicating with the intended website without interference from attackers." - [wikipedia](https://en.wikipedia.org/wiki/HTTPS)
  
HTTPS provides **end-to-end encryption of traffic** between the client's browser and the server.



## Use cases
* Avoid interception of messages (by someone looking at the traffic)
* Ensure integrity of data (content of the pages can not be modified before arriving to the receiver)
* Protect users privacy
* Authenticate domains (and websites running on those domains) with the help of SSL Certificate Authorities (CA) and SSL certificates
* Faster loading times than HTTP/1.1 (see [HTTP vs HTTPS](https://www.httpvshttps.com/))

HTTPS helps against script injections (cryptominers, keyloggers, ads...), DOM page modification, DNS spoofing, CSRF attacks on routers. These attacks are enabled on HTTP when one gets access to traffic (ex: at a proxy level) where they can see the traffic and inject payloads or modify the page before it reaches the user's browser. HTTPS is necessary even on static web pages, see this video: [Here's Why Your Static Website Needs HTTPS](https://www.youtube.com/watch?v=_BNIkw4Ao9w).

*Note: HTTPS does not mean you can have full trust to the website you are connecting to. It only means your connection is private. It cannot be eavesdropped and its traffic can't be modified by a man in the middle.*
> "HTTPS & SSL doesn't mean "trust this." It means "this is private." You may be having a private conversation with Satan. - [Scott Hanselman tweet](https://twitter.com/shanselman/status/187572289724887041)



## Protocol : TLS
*TLS summarized:* client connects to the server (**handshake** begins) and verifies the authenticity of the server (via its SSL certificate and the help of Certificate Authorities). Client and server then safely agree on a **secure cipher suite** to use for the rest of the communication. Some **shared secrets are exchanged** depending on the cipher suite chosen (handshake ends). Then the rest of the communication is encrypted before being sent and decrypted on reception (for both ends).

See the [**Transport Security Layer (TLS)**](#tls) section for a detailed explanation of the protocol.

### HTTPS configuration
HTTPS is usually configured on the web server hosting the website/application (or the proxy in front of the application, ex: Cloudflare hosting/'proxy'). The web server (nginx/apache/traefik/...) has configuration files that define how it should behave when getting a request or when sending a response. The configuration specifies what protocol the server support (TLS 1.2, TLS 1.3), the cipher suites available, the HTTP(S) ports, the SSL certificate info. The web server can redirect traffic to HTTPS automatically, add security headers to outgoing requests ([HSTS](#hsts), [CSP](#csp), ...). Tools and resources can guide you to generate and verify the configuration of your web server:

* [Mozilla SSL Configurator](https://ssl-config.mozilla.org/) - SSL configuration generator (for nginx/apache/traefik...)
* [Scott Helme HTTPS Cheat Sheet](https://scotthelme.co.uk/https-cheat-sheet/) 
* [SSL Labs](https://www.ssllabs.com/ssltest/index.html) - test your HTTPS config
* [SecurityHeaders.io](https://securityheaders.io/) - test your security headers

**The configuration is key to ensure the security of the application**. A misconfigured server or a server enabling old/discarded protocols/features can compromise the application and the HTTPS connection.

### HTTP/2
  
  > TODO


## HSTS (HTTP Strict Transport Security) <a id="hsts"></a>
* **_Strict-Transport-Security_** HTTP **response header**  
* **How it works**: a **response header** is returned by the server and says 'For the next X seconds (maxAge), the browser may not make an insecure request on this domain. It should be used with [**preloading**](#preload) for maximum security (preload = if the user has never been on the website before, it will ensure it loads over HTTPS even on the first connection, even if the user does not specify https://).
  
By default in browsers, the first request goes through HTTP if HTTPS is not specifically mentionned, and usually the server will return a 301 Redirect to use HTTPS instead. If HSTS is set, then **all the requests after the first one will ensure the use of HTTPS (until maxAge)** even if the user sends an HTTP request (ex: by not specifying https:// or clicking an HTTP link/bookmark). See [RFC#6797](https://tools.ietf.org/html/rfc6797).

*ex: strict-transport-security: max-age=31536000; includeSubDomains; preload*

### More on HSTS

* [Understanding HTTP Strict Transport Security (HSTS) and preloading it into the browser - Troy Hunt](https://www.troyhunt.com/understanding-http-strict-transport/)
* [Scott Helme HSTS Cheat Sheet](https://scotthelme.co.uk/hsts-cheat-sheet/)

> TODO Research about the 'Trust On First Use' problem (TOFU) - is the initial request being secured? Usually (without HSTS and preload), the first connection is insecure and then the connection becomes secure


## Preloading <a id="preload"></a>
Websites that use HSTS and the **preload option** ensure only HTTPS requests can be used between the client and the server (even if the user has never been there before, it will only be loaded over HTTPS no matter what - browser does a 307 Internal Redirect). **Preloaded website lists are embedded directly in browsers binaries** (see [HSTSpreload.org](https://hstspreload.org/) for submissions) and **the browser itself forces the use of HTTPS from the first request**. It should be used for the entire site and its subdomains.

> "However, be aware that inclusion in the preload list cannot easily be undone. Domains can be removed, but it takes months for a change to reach users with a Chrome update. Don't request inclusion for HSTS preloading unless you're sure that you can support HTTPS for your entire site and all its subdomains in the long term." - from [hstspreload.org](https://hstspreload.org/)

* **HSTS + preloading** should be considered the standard for security

Using HSTS and preload option with a website that does not serve everything over HTTPS will completely block users from accessing your website as the browsers will block connections when they see HTTP content (HTTP content is not allowed on HSTS preloaded websites). You need to be cautious when configuring HSTS and preload option and test your entire app before you fully commit and submit your site to the preload list. See [HTTPS is easy - a guide by Troy Hunt](https://httpsiseasy.com/) to get a good understanding on how to configure HTTPS, HSTS and preload option.


## DNS over HTTPS (DoH)
> TODO Research this, see: [wikipedia](https://fr.wikipedia.org/wiki/DNS_over_HTTPS)   
> Option to enable in the browser (exists on Mozilla but not Chrome?)



## More on HTTPS and how to implement it

* [Mozilla guidelines on web security](https://infosec.mozilla.org/guidelines/web_security)
* [Google guidelines on web security](https://developers.google.com/web/fundamentals/security/?hl=en)
* [Does my site need HTTPS?](https://doesmysiteneedhttps.com/)
* [What is an SSL certificate? - Cloudflare](https://www.cloudflare.com/learning/ssl/what-is-an-ssl-certificate/)
* [Let's encrypt FAQ](https://letsencrypt.org/docs/faq/)
* [HTTPS is easy - a guide by Troy Hunt](https://httpsiseasy.com/) - *"Troy Hunt is a Microsoft Regional Director and MVP, web security expert known for public education and outreach on security topics" (wikipedia). He also runs a [blog (troyhunt.com)](https://www.troyhunt.com/) with knowledgeable content about web security and his [Have I Been Pwned](https://haveibeenpwned.com/) project.*
* ["What Every Developer Must Know About HTTPS"](https://www.pluralsight.com/courses/https-every-developer-must-know): Pluralsight course on HTTPS


## Mobile apps
 **Mobile apps** do not have a browser to warn the user if the connection is using HTTPS or not. There is no certificate validatiton insurance either and no padlock to see the HTTPS status (whereas those infos are displayed in browsers). A lot of mobile apps traffic (that is not using a browser) is insecure (using HTTP, sending credentials with HTTP before getting redirected to HTTPS etc).

<br>

# 2. TLS (Transport Layer Security) <a id="tls"></a>

## TLS
>TODO



## TLS 1.2 (since 2013) vs TLS 1.3
>TODO



## 0-RTT (Zero Round Trip Time Resumption mode)
>TODO [cloudflare blog](https://blog.cloudflare.com/introducing-0-rtt/), [ssl.com article](https://www.ssl.com/faqs/network-attacks-and-security-issues/), [LDAP wiki](https://ldapwiki.com/wiki/0-RTT%20Handshakes), [another article](https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/)


### More on TLS
> TODO


## Vulnerability disclosure on web applications
### security.txt
The security.txt standard was created by security researcher [@EdOverflow](https://twitter.com/edoverflow) and offers a simple solution for security researchers or anyone finding a vulnerability in an application to get contact information \(usually an email adress\) to get in touch with the right team and address the security issue. This **security.txt** text file is sitting in the **.well-known directory** at the root of the application. It can contain information such as:  

* contact information to reach the security team (email address)
* the company's policy regarding responsible discloures and the process to handle those
* a PGP public key to send encrypted emails to the security team

Few websites use this standard but it is gaining popularity and you can find security.txt examples on websites such as Google, Facebook, Dropbox, ...  
See:

* [https://www.google.com/.well-known/security.txt](https://www.google.com/.well-known/security.txt), [https://www.facebook.com/.well-known/security.txt](https://www.facebook.com/.well-known/security.txt)
* [Crawler.ninja analysis](https://crawler.ninja/files/security-txt-sites.txt) on security.txt files in top 1 million websites

<br>

# 3. Content Security Policies (CSP) <a id="csp"></a>
The [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) is an HTTP response header that can help mitigate XSS/data injection/clickjacking attacks. If the CSP header is not defined, browsers usually use the [Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy). "The **Same-origin policy** restricts how a document or script loaded from one origin can interact with a resource from another origin. It helps isolate potentially malicious documents, reducing possible attack vectors." - Mozilla MDN *(most of the content from this CSP section comes directly from the [Mozilla MDN CSP page](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP))*.

A CSP response header is a simple string containing the policy: 

```
"Content-Security-Policy: policy"
```

## Implementing a Content-Security Policy
In order to use the CSP, the web server should add the header to every HTTP response. CSP implementation can be done in a few steps:

1. **Specify the CSP**: what resources from the web page should be allowed to load from where
2. **Write the policy**: a policy is the string you place in the header that defines the CSP behaviour using a series of policy directives (keywords to specify how to handle each resource type)
3. **Test the policy**: The HTTP header **Content-Security-Policy-Report-Only**: *policy* can be used to deploy a policy and test it on a live application. Any policy violations will get reported to the provided URI. If both headers are present, the CSP header is enforced and the CSP report header is only used to generate reports but is not enforced on the page.
4. **Enable reporting**: using the **report-uri** directive in the CSP and then process the reports on your server

```
Content-Security-Policy: default-src 'self'; report-uri http://reportcollector.example.com/collector.cgi
```

## Reminders
"Your policy should include a **default-src** policy directive, which is a fallback for other resource types when they don't have policies of their own. For a complete list, see the description of the [default-src directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src)" - Mozilla MDN. One ore more sources can be allowed for the default-src directive, see:

```
Content-Security-Policy: default-src <source>;
Content-Security-Policy: default-src <source> <source>;
```


**There is no inheritance with the *default-src* directive**, any directive specified with the default one will override the behaviour.

```
Content-Security-Policy: default-src <source>; script-src: <source2> // only source2 scripts are allowed
```

The **'self'** attribute refers to the origin from which the protected document is being served, including the same URL scheme and port number. The single quotes are required.

Google made the [CSP Evaluator](https://csp-evaluator.withgoogle.com/) tool to help developers test CSPs and see if they have insecure policies or important missing policies.


## CSP examples
A few common CSP examples taken from the [Mozilla MDN CSP page](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP):

#### All content must come from the website own domain (exclude its subdomains)

```
Content-Security-Policy: default-src 'self'  
```

#### All content must come from the website own domain or a trusted domain and its subdomains

```
Content-Security-Policy: default-src 'self' *.trusted.com
```

#### Specify images, media, scripts domains
In the example below, by default the content must come from the website own domain with the exception of:   

- images can come from any domain
- scripts are only allowed to come from a specific server (subdomain of example.com)
- videos/media must come from a specific domain (and not his subdomains)


```
Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com
```

#### Ensure all content is loaded through HTTPS (by specifying the origin domain with HTTPS)

```
Content-Security-Policy: default-src https://onlinebanking.jumbobank.com
```

## Strict-dynamic directive
A directive to simplify the implementation of CSPs for scripts as the policies can sometimes be bypassed and can be hard to maintain (partly because scripts are often served by CDNs which can change). This directive relies on **hashes** or **nonces attributes** specified with the script tag. "It allows scripts which are given access to the page (via nonces or hashes) to bring in their dependencies without adding them explicitly to the page’s policy" - W3.org. Only non-"parser-inserted" script elements (inside a script) are allowed to be loaded on the page (see [W3.org strict dynamic usage](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage) for a better explanation).

For example, the following *script.js* is loaded within a page with the CSP header set below:

```
Content-Security-Policy: script-src 'nonce-DhcnhD3khTMePgXwdayK9BsMqXjhguV' 'strict-dynamic'
```

```
<script src="https://cdn.example.com/script.js" nonce="DhcnhD3khTMePgXwdayK9BsMqXjhguVV" ></script>
// request to cdn.example.com won't be blocked because of the nonce attribute
```

Depending on how dependencies are added within *script.js* (other scripts loaded inside the script), they will be allowed or blocked from loading in the page. An example of a **"parser-inserted" script** element that would be blocked: 

```javascript
document.write('<scr' + 'ipt src="/sadness.js"></scr' + 'ipt>');
```

However, this script would be allowed within script.js (*not a parser-inserted script*):

```javascript
var s = document.createElement('script');
s.src = 'https://othercdn.not-example.net/dependency.js';
document.head.appendChild(s);
```


> TODO Research more on this
> 
* [W3.org strict dynamic usage](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage)
* [strict-dynamic CSP directive](https://content-security-policy.com/strict-dynamic/)
* [csp.withgoogle.com FAQ](https://csp.withgoogle.com/docs/faq.html)

## Upgrade-insecure-requests directive

> TODO [Mozilla upgrade-insecure-requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests)

## More on Content-Security Policy

* [Mozilla CSP documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
* [Google CSP documentation](https://developers.google.com/web/fundamentals/security/csp)
* [Scott Helme CSP Cheat Sheet](https://scotthelme.co.uk/csp-cheat-sheet/): a guide on CSP explaining the different directives available, and additional useful resources* [W3.org CSP2 Specification](https://www.w3.org/TR/CSP2/)
* [CSP Quick Reference Guide](https://content-security-policy.com/) - a guide/cheat sheet on CSP by Foundeo
* [Google CSP evaluator](https://csp-evaluator.withgoogle.com/) - a tool to review CSP policies and help identify CSP bypasses
* Related [X-Frames-Options header](https://infosec.mozilla.org/guidelines/web_security#x-frame-options) to restrict how a website can be embedded in an \<iframe> within itself or from another domain. It can be coupled with the **frame-ancestors** CSP directive
* More on the **[strict-dynamic CSP directive](https://content-security-policy.com/strict-dynamic/)** that can be used to specify that a root script is allowed to be loaded on the page (and other scripts loaded within the root script are also allowed) by using a *nonce* or a *hash* inside the script tag attributes.




# Same-origin Policy <a id="sop"></a>
> TODO  
> 
> [Same-origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
> 


# Cross-Origin Resource Sharing (CORS) <a id="cors"></a>
> TODO  
> 
> [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
> [Wiki CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing)
> [CORS Glossary](https://developer.mozilla.org/en-US/docs/Glossary/CORS)
> [CORS Safelisted Request Headers](https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header)



## Certificates
> TODO  
> [Mozilla Certificates Transparency](https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency)

## Certificates Authorities
> TODO Also look at reports from [Crawler.ninja tool]([https://crawler.ninja/](https://crawler.ninja/) (from Alexa Top 1 million websites visited) for infos about the use of HTTPS, Certificates and other features (ex: [March 2020 report](https://scotthelme.co.uk/top-1-million-analysis-march-2020/))


<br>

# 4. HTTP Headers and Cookies <a id="headers"></a>

## HTTP Request Headers
> TODO
> Host, Referer, Origin, X-Forwarded-Host, ...
> [Mozilla Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
> 
> 
## HTTP Response Headers

| Header | Description| Example |
|------|---|---|
| **[Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)** | Control resources the user-agent is allowed to load (helps against XSS attacks). Specify allowed server origins and script endpoints. See [CSP section](#csp)|Content-Security-Policy: default-src 'self'; img-src 'self' https://i.imgur.com; object-src 'none'; **upgrade-insecure-requests**|
| **[Strict-Transport-Security](https://developer.mozilla.org/fr/docs/S%C3%A9curit%C3%A9/HTTP_Strict_Transport_Security)** | Enable HSTS (and preload) | Strict-Transport-Security: max-age=31536000; includeSubDomains; preload|
| **[X-Content-Type-Options](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options)** | Prevents browsers from MIME-sniffing away from the declared Content-Type | X-Content-Type-Options: nosniff|
|**[X-Frames-Options](https://infosec.mozilla.org/guidelines/web_security#x-frame-options)**|Control how your site may be framed within an iframe (and avoid clickjacking attacks)|X-Frame-Options: DENY|
|**[X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)**|Feature of some browsers (Safari/IE) to block XSS attacks detected by the browser (with a reporting functionnality). **No longer works on Chrome**. See [X-XSS-Protection section](#x-xss-protection-header)|X-XSS-Protection: 1; report=\<reporting-uri>|

## Cookies
### HTTP Only
An HTTP Only cookie can't be read by a clientside script. So if an attacker gets an XSS on the page, it can't access this cookie.
> TODO Defense against XSS attacks from other domains accessing the cookies? Research this

### Secure
Ensures that the cookie will never be sent over an insecure connection (HTTP request) --> always sent with HTTPS. Avoids MitM attacks intercepting this value.
> TODO

### SameSite
SameSite is a cookie attribute (from the Set-Cookie response header) which aims to mitigate CSRF attacks (can [sometimes](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1) be bypassed). It helps the browser decide whether to send cookies along with cross-site requests. Possible values for this attribute are:

* **Lax**: send the cookie except on certain CSRF-prone request methods such as POST/PUT - only send for top-level navigation (such as clicking a link, requests made by JavaScript do not include the cookie) using safe HTTP methods ex: GET, HEAD, OPTIONS. *(default value for cookies in Chrome since Feb. 2020)*
*  **Strict**: never send the cookie from a cross-site context, ex: when clicking on a link from an external website

* **None**: always send the cookie *(cookies set as SameSite None require the Secure attribute in Chrome)*

> Set-Cookie: JSESSIONID=xxxxx; SameSite=Strict  
> Set-Cookie: JSESSIONID=xxxxx; SameSite=Lax

Limitations: 

- if a website uses a GET method to perform a state update action (ex: changing password or email) then it can be abused as it does not do anything on GET requests.  
- some frameworks are tolerant to different HTTP methods, a request could be accepted as a GET request even if it will be resolved by design using the POST request route/controller (thus bypassing the SameSite cookie attribute)


### More on SameSite
- [OWASP CSRF Prevention - SameSite cookie attribute](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute)
- [IETF definition of SameSite cookie attribute](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1)
- [PortSwigger - Defending against CSRF with SameSite cookies](https://portswigger.net/web-security/csrf/samesite-cookies)

### More on HTTP headers and cookies
> TODO



<br>

# 5. Attacks overview <a id="attacks"></a>

## Clickjacking attacks
> TODO [OWASP Defense CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), ...


## SSL stripping
 **MITM attack** where the attacker communicates with the victim over HTTP and relays the requests to the server over HTTP(S). That way the attacker sees all the client's traffic over HTTP. (The victim's connection is 'stripped' of SSL and downgraded to HTTP).

An introduction to a MitM SSL stripping attack using Karma and SSLstrip: [the WiFi Pienapple](https://scotthelme.co.uk/wifi-pineapple-karma-sslstrip/).


## XSS (Cross-Site Scripting)
> TODO

A XSS is a technique to execute your own javascript on the domain of an application.
### XSS Cheat Sheets
- [PortSwigger - XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP - XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

### Stored XSS
The payload is sent to a database and is stored there and is called every time a user visits the page where its resource is loaded (ex: sending a XSS payload through a form input which value is later embedded on the page without being sanitized properly).

Note: *Blind XSS* are a type of stored XSS where you don't have access to the page that triggers the XSS (admin panels, ...) --> [XSS hunter](https://xsshunter.com/) tool to help find blind XSS?

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
The XSS payload input is not stored in a database but reflected on the page or on some other page. Using malicious links you could send to users, you could execute a payload on the user's page.

#### X-XSS-Protection header <a id="x-xss-protection-header"></a>
The [X-XSS-Protection response header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)  is a feature of web browsers to detect reflected cross-site scripting (from the URL content) and block the payload from executing JavaScript code. **Chrome completely disabled the XSS_AUDITOR and the use of the X-XSS-Protection header** since Chrome 78 (~August 2019, see [note1](https://www.chromium.org/developers/design-documents/xss-auditor), [note2](https://www.chromestatus.com/feature/5021976655560704)). The response header does not exist in Firefox and Edge retired their XSS filter. It works on Safari, and Internet Explorer.


```
X-XSS-Protection: 0 // protection disabled
X-XSS-Protection: 1 // protection enabled
X-XSS-Protection: 1; mode=block // blocks the entire page from rendering
X-XSS-Protection: 1; report=<reporting-uri> // enable protection and send a report of the XSS to a URI
```



## CSRF (Cross-Site Request Forgery)
### Definition
CSRF is a type of attack to make people send unintentionnal requests to a target domain (on which they are logged in and can perform specific actions - ex: change their password).

Attackers can execute **forged requests** (trick the browser to issue an authenticated request to the server without the logged in user knowing) by using the user's **auth cookie**. Usually a CSRF attack is done when a user is visiting a malicious page (or a page embedding a malicious ad) that sends a request to a website they are currently logged in and takes advantage of their auth cookie to perform an authenticated action. The malicious page only has to replicate the original request (same url, payload, method) and the auth cookie will be sent automatically by the browser. Typically, the form+submit action can be stored in a hidden \<iframe> and the user won't notice anything when visiting the malicious page.

What does a CSRF request look like? It is the same as the actual request to perform the action: request URL + request method + payload (+auth cookie). **An auth cookie is sent with each request after you have logged in** (which lets the server know who you are). **Cookies are automatically sent by the browser with each request for the domain (if not expired)**.

CSRF happens because the request is predictable (url, method, data). In order to protect an action, you need to add unpredictability (aka **CSRF token/anti-forgery token**) and validate it on the server.

### Token-based CSRF mitigation
Different patterns using a CSRF token can be used to mitigate CSRF attacks, according to the OWASP cheat sheet: 

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

Sometimes, the website only stores the CSRF token clientside and does not maintain a list of valid issued tokens on the server. It only generates a CSRF token clientside and the server validates that the csrf param in the request has the same value as the CSRF cookie. This is sometimes called the "double submit". It's a simple defense to implement against CSRF and avoids the need for any server-side state. The attacker can perform a CSRF attack if the website contains any cookie setting functionality. He does not need to obtain a valid token but can simply invent a token (with a valid-like format), and set the cookie into the victim's browser for the CSRF attack. _(mostly paraphrased from section "CSRF token is simply duplicated in a cookie" in the above PortSwigger link)_


### Other mitigation techniques:

- **Referer request header** and strict Referer policy on login pages (see [Robust Defenses for Cross-Site Request Forgery paper](https://seclab.stanford.edu/websec/csrf/csrf.pdf))
- Use of **custom request headers** especially on AJAX/XHR calls: "this defense relies on the same-origin policy (SOP) restriction that only JavaScript can be used to add a custom header, and only within its origin. By default, browsers do not allow JavaScript to make cross origin requests with custom headers." - [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers)
- User based interaction (re-authentication via password or stronger like 2FA, one-time tokens, CAPTCHA) for specific requests that need strong CSRF protection (transfering funds, modifying a password...)

*Note 1: Many frameworks have __built-in CSRF protection__. Avoid re-implementing it yourself...*  
*Note 2: XSRF is the same acronym as CSRF*

### More on CSRF
* [Understanding CSRF](https://www.youtube.com/watch?v=hW2ONyxAySY) - a tutorial video by Troy Hunt
* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) - OWASP guidelines
* [PortSwigger CSRF](https://portswigger.net/web-security/csrf) - article & labs
* [Defending against CSRF with SameSite cookies](https://portswigger.net/web-security/csrf/samesite-cookies) - PortSwigger article
* [Common CSRF prevention misconceptions](https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2017/september/common-csrf-prevention-misconceptions/)
* [Robust Defenses for Cross-Site Request Forgery](https://seclab.stanford.edu/websec/csrf/csrf.pdf) research paper


## SSRF (Server-Side Request Forgery)

> TODO

### Definition
SSRF is a vulnerability where an attacker forces a server to perform requests (usually a HTTP request but the server can often use many different protocols). The crafted HTTP request sent by the attacker with a payload triggers the server-side request. This attack is similar to CSRF (unintentional requests being executed) but here the victim is the vulnerable server.

...

### Exploitation
> What type of attack (LFI?, XXE?, improper input validation ex: with SVG uploads/rendering, ...), what is the goal (pull data out of the server, get a shell on the server to have RCE, priviledge escalation, leak files, leak services running)
...

### Mitigation

...

### More on SSRF

* [SSRF CheatSheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/server-side-request-forgery)
* [SSRF explanation article](https://medium.com/bugbountywriteup/server-side-request-forgery-ssrf-exploitation-technique-9bc4b4045fbd)
* [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
* [SVG SSRF CheatSheet](https://github.com/allanlw/svg-cheatsheet)


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

# 6. Miscellaneous <a id="misc"></a>

## VPNs (Virtual Private Networks) <a id="vpns"></a>

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

*ex: NordVPN*

### More on VPNs
> TODO


<br>

# 7. Other resources <a id="resources"></a>

## Documentation
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [Mozilla Web Security](https://infosec.mozilla.org/guidelines/web_security)
* [Google Web Security](https://developers.google.com/web/fundamentals/security/?hl=en)
* 


## Blogs / Articles / Videos
* [Troy Hunt Blog](https://www.troyhunt.com/)
* [We didn't encrypt your password, we hashed it. Here's what that means](https://www.troyhunt.com/we-didnt-encrypt-your-password-we-hashed-it-heres-what-that-means/) - the difference between hashing and encrypting data
* [Here's Why Your Static Website Needs HTTPS](https://www.troyhunt.com/heres-why-your-static-website-needs-https/) - the use of HTTPS even on static websites
* [Attacks on web applications: 2018 in review](https://www.ptsecurity.com/ww-en/analytics/web-application-attacks-2019/) - statistics on the most common web application attacks in 2018 (from a [ptsecurity](https://www.ptsecurity.com/ww-en/) study)
* [What Every Developer Must Know About HTTPS](https://www.pluralsight.com/courses/https-every-developer-must-know) (3h30min course on Pluralsight)
* [Hack to the Future](https://www.youtube.com/watch?v=kIo7DNAd_oo) - a talk by Troy Hunt at the NDC Oslo 2019 conference


<br>

# 8. Glossary <a id="glossary"></a>

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
|SSRF|Server-Side Request Forgery|
|TLS|Transport Layer Security|
|WAF|Web Application Firewall|
|XXE|XML External Entity|