---
sidebar_position: 3
---

# Node.js Security

## Validating Data in ExpressJS

### WHAT IS UNTRUSTED DATA?

- **Untrusted data** is any data that comes into your application (whether from a form on your website that a user fills out, the HTTP request headers that you receive from the browser, or even data from a database you control) that has not been vetted and validated by your application.

### WHERE TO VALIDATE DATA

- The common places you will encounter data validation are at the client side when the request is received, and at the database layer when processing database queries.
- You also need to implement data validation on the server side as the request is received and before anything is persisted to the database.

### VALIDATING DATA AT THE REQUEST LAYER

`npm install express-validator --save`

```js
const bodyParser = require("body-parser");
const express = require("express");
const { checkSchema, validationResult } = require("express-validator");
app.use(bodyParser.json());
```

## Handling Authentication in NodeJS Applications

### PROTECTING PASSWORDS

- Bad practices used for storing passwords, such as:
  - storing them in plaintext
  - using encryption
  - using insecure hash functions

:::danger

- Passwords should never be stored using encryption.
- If a user's plaintext password can be retrieved (or decrypted) from the database by an application or by a database administrator, it is not being stored securely.
  :::

:::info

- Cryptographic hashing algorithms such as SCrypt and BCrypt are BEST PRACTICE for protecting passwords.
- These algorithms are “future-proof” in that they allow developers to set what is known as a work factor.
- The work factor controls how many iterations are required by the algorithm.
  :::

- Cryptographic hashing algorithms are designed to be slow.
  - When an attacker is trying to brute-force an entire database of passwords hashed using one of these functions, their efforts will slow to a crawl.
  - As cracking technology evolves, these algorithms can easily evolve as well by increasing the work factor to keep up, without changing any of the password authentication code.

`npm install --save bcrypt`

### PROTECTING AGAINST USER ENUMERATION

:::danger

- Enumeration is bad practice, where different error messages are returned depending on which field was entered incorrectly. - Example: The user entered the username incorrectly, and a Hacker can know they need to focus on cracking the username first.
  :::

### LOCKING USER ACCOUNTS

- If an attacker knows that a user account exists, they may attempt to learn the password by performing a brute-force attack against the user's account.
- To prevent this kind of abuse, you need to track the number of failed attempts against an account during the authentication process.
- By tracking the failed attempts, you can lock out further login attempts after a set number of failures.
- The account can automatically reset after a period of time, or a manual reset can be used to re-enable the account (after the legitimate user is properly vetted, of course).

#### KNOWLEDGE CHECK

- When storing passwords, why is bcrypt a good choice for password hashing?
  - It is designed to be slower than other hashing algorithms.
- True or False: Passwords should never be stored using encryption.
  - True

## Access Control in NodeJS

### PRINCIPLE OF LEAST PRIVILEGE AND ROLES

- The principle of least privilege states that any process or user should have only the privileges required to carry out their tasks and no more.
- Routine auditing of user accounts and the privileges in the system is a good defense-in-depth strategy.
- Role-based access control:
  - Example: Customer Service, Accounting, or Admin priviledges are unique from each other.

### FUNCTION-LEVEL ACCESS CONTROLS

- Need to perform server-side access checks to restrict specific actions.

:::tip

- It is a good idea to centralize these access control checks.
- If any bugs are discovered, they can be fixed in one place.

:::warning
If access control checks are spread throughout the code base, it can lead to an overly complex access control code that will result in these checks being missed.
:::

:::

### ACCESS CONTROL MISTAKES

- Examples of Mistakes:
  - forgetting to perform a check
  - only checking for a role and not privilege.

:::tip
A good defense-in-depth strategy is to routinely audit the endpoints in the application and what roles and privileges should be required to access them: make sure that the proper access controls are in place.
:::

#### Knowledge Check

- An API needs to be secured that supports multiple HTTP methods. Where should the access control check be performed to see if the user can access the endpoint?
  - In the all route handler

:::tip

- If a single endpoint requires access control checks, it should be handled in the all route handler.
- Even if the endpoint currently only uses the when method, handling it in the all handler will protect against mistakes in the future.
- Additional access control checks can be performed in the individual route handlers if more fine-grained privileges are used.
  :::

- True or False: Because it is typical for an application to have numerous privileges, it is best to assign those privileges individually by user.
  - False

## Session Management in ExpressJS

### OVERVIEW

- One of the most important pieces of information to protect is the session identifier assigned to a user.
- If an attacker can acquire a valid session identifier that is assigned to another user, they can use this to authenticate to the application as that user, with all of that user's privileges.

### SESSION HIJACKING

- Easiest way a session identifier can be compromised is through unintended leakage.
  - If the session identifier is being sent over an insecure channel and the user is in a situation in which an attacker can view their network traffic, then this may be the result of a **person-in-the-middle (PITM) attack** at a public location (for instance, a coffee shop) or someone that has access to the internal application network.
  - Since the session identifier is sent on every request, it provides an attacker with many opportunities to steal it.
- If the application has a **cross-site scripting (XSS) vulnerability**, an attacker can steal the user's session identifier through executing JavaScript that sends the session identifier to a remote server.
  - The attacker can then use this session identifier to log in to the application as that user.
  - Fortunately, this can be easily prevented by the use of the HttpOnly flag when setting the cookie.
  - This flag will instruct the browser to allow access to the cookie only on HTTP requests.
  - If any JavaScript code, legitimate or otherwise, attempts to access the cookie, the browser will just return null.

### ENABLING HTTPONLY FLAG

`npm install express-session --save`

`npm install connect-mongo --save`

### ENABLING THE SECURE FLAG

- You can prevent a cookie from being sent over an unencrypted connection by using the secure cookie flag.
- When set, this flag tells the browser that the session cookie should never be sent over an unencrypted connection.
- This will prevent an attacker from being able to easily eavesdrop on the network requests and steal the session identifier.

:::warning

- This strategy, like all strategies, is not foolproof, but adds another layer to the security-in-depth approach.
- If any part of the application is still using an insecure connection, this may break current functionality.
  :::

### SESSION TIMEOUTS

- Easiest safeguards is to use session timeout.
- By implementing a session timeout, your session will automatically be destroyed after a specified period of inactivity.
- If the user makes a request after this time, they will need to authenticate again.
- This way, if a user on a public computer forgets to log out of the application, an attacker can't access the app using that person's session.

### SESSION FIXATION

:::warning

- **Session fixation** can occur when you recycle session identifiers.
  - For example, if a user visits your site and you set a session identifier before they log in, and then you allow them to keep the same session identifier after they authenticate to your application, you are recycling session identifiers.

:::danger

- Depending on how the vulnerable application is handling session identifiers, an attacker can create a situation in which the user will authenticate to the application but end up using a session identifier that the attacker controls.
- This can be done through an XSS vulnerability and could, for example, be used by an attacker who has legitimate access to the application to take over an administrative account.
  :::
  :::

- To protect users from session fixation attacks, you need to assign a new session identifier to the user after they authenticate.
  - Any existing session identifier is simply ignored or invalidated, and a new one is always assigned.
  - By doing this, even if an attacker can create a situation in which the user received the session identifier that the attacker wants, the user will receive a new one after authentication, preventing the attacker from being able to access the application as the user.

### FORCING RE-AUTHENTICATION

- You can further protect user accounts by forcing the user to re-authenticate under certain circumstances, like before changing their password or contact information.

:::warning

- The ability to change this information is often exploited by attackers: after gaining access to an account, they lock the user out of their account and take control of it.
- If the attacker has gained access to a user account through stealing a session identifier, the attacker will not know the user's password.
- If you require another authentication before allowing any of these changes to be made, you can prevent an attacker from taking over the account.
  :::

#### KNOWLEDGE CHECK

- The loss of a user session identifier can lead to:
  - session hijacking
- True or False: Session fixation can occur when you recycle session identifiers.
  - True

## NodeJS Transport Security

### OVERVIEW

- One of the most important things you can do to protect your application and its users is use a secure communications layer between the user and the application.
  - This is known as **Transport Layer Security (TLS)** and it prevents unintended data leakage, as well as preventing an attacker from eavesdropping on your traffic.
  - Using TLS also has the added benefit of ensuring that the site you are interacting with is the authentic site, and that you are not being redirected to a fake site.

### TLS, SSL, AND HTTPS

- SSL: Secure Sockets Layer
- Transport Layer Security (TLS) can refer to any secure communications channel and does not specify a specific protocol that must be used.
- HTTPS is the use of HTTP over an established TLS tunnel, and is not a different protocol.

:::warning
You should use TLS version 1.2 or later, as SSL has been deprecated due to cryptographic flaws.
:::

#### Quick Question

- As of 2018 the NSA recommends using these transport security Methods?
  - TLS 1.2 and TLS 1.3

### IMPORTANCE OF TLS

- TLS allows you to share confidential or private data between users and your application.
- TLS also validates that the user is interacting with the site that they intend to.
- During the TLS handshake that establishes the secure connection, the server presents their certificate for validation by the browser through public key encryption and the use of certificate authorities.
- The site's certificate is checked against the list of certificate authorities that is pre-loaded into web browsers.
- All certificates need to be signed by a trusted certificate authority; if the certificate can't be validated, it is likely something is amiss and the site should not be trusted.
- Along with validating who you are communicating with, TLS also provides message integrity, which ensures that the message has not been tampered with during transit.

### HTTP STRICT TRANSPORT SECURITY HEADER

- Any time a connection is not secured, there is a chance that an attacker can see your traffic.
- Even if you redirect the user to an HTTPS version of the application, the user could still be directed to an HTTP version if it is still supported.
- The HTTP Strict Transport Security (HSTS) header instructs the browser to force all future connections to a site over HTTPS.
- This prevents an attacker from directing a user to an insecure protocol (HTTP) after the user has already been to your site.

:::warning

- Never serve the HSTS header over an insecure connection.
- When redirecting the user, an HTTP 307 redirect should be used to preserve the request method (a 302 or 303 redirect is not handled properly among modern browsers due to legacy issues).
- Once the connection is established over HTTPS, the HSTS header should always be issued.
  :::

- The helmet package is a collection of middleware that adds additional HTTP headers to your application to increase security.
- It also removes headers that might leak information, such as the X-Powered-By HTTP header.

`npm install --save helmet`

### CONTENT SECURITY POLICY

- You can add an additional layer to your application’s security and take XSS mitigation much further by implementing a **Content Security Policy (CSP)** header.
- This header helps reduce XSS risks, as well as other injection attacks, by allowing you to declare what dynamic resources are allowed to be loaded and where they should be loaded from.
- You can also instruct the browser to send violations to a configured endpoint, where you can log data about the violation so that you can fix it.
- The Content Security Policy header is a single HTTP header composed of various directives that instruct the browser as to how it should handle certain requests.

#### Knowledge Check

- A Content-Security-Policy header will aid in preventing which of the following attacks?
  - Cross-site scripting (XSS)
- True or False: Any time a connection is not secured, there is a chance that an attacker can see your traffic.
  - True

## Pug Security Concern

- The most common (and default) is Pug system as a common templating system.

### CROSS-SITE SCRIPTING

- Pug will automatically escape any data to prevent injection attacks, but it also allows for user input to be inserted without escaping.
- **Buffered code** is started with `=` and code is HTML-escaped first:
  `p= 'This <script> tag will be escaped!'`
- Buffered code can be unescaped by using the `!=` syntax:
  `p!= 'This <script> tag will NOT be escaped!'`

:::danger
Using != is dangerous and can result in HTML injection and XSS flaws. Be careful!
:::

#### String Interpolation

- Pug provides operators for interpolating strings with variables and user data. It comes in two forms: an escaped version and an unescaped version.
  - The most common interpolation syntax, `#{ }`, performs escaping.
  - By using `!{ }` you can output unescaped HTML.

### COMMON USED TEMPLATING SYSTEMS

- Hogan
- Handlebars
- EJS
- Pug

#### KNOWLEDGE CHECK

- You need to output untrusted data within an HTML div tag using Pug. Which of the following will ensure that you do not risk an XSS vulnerability?
  - Using the `#{}` operator.
- Pug uses different mechanisms for handling user input in templates. Which uses `!=` and can result in HTML injection?
  - Unbuffered Code

## Preventing MongoDB Query Selector Injection Attacks

### OVERVIEW

:::warning

- NoSQL databases are more susceptible to injection attacks, as the query language being used does not feature escaping or parameterized queries. - Since there are no parameterized queries in the database engine, it is up to the developer to ensure that the NoSQL queries are constructed properly.
  :::

### INJECTING JAVASCRIPT

- The following commands and operators all allow arbitrary JavaScript expressions to be executed on the server
  - `$where` operator
  - mapReduce command
  - group command

:::danger

- An attacker who can influence what is being passed into these commands or operators can leverage this to interact with the database. - And even gain remote access to the server itself.
  :::

### INJECTING OPERATORS

- Depending on how the query to MongoDB is being handled, if input is not sanitized, you run the risk of an attacker injecting query modifiers into your code.
  - In order to prevent this, you need to sanitize the request.

#### KNOWLEDGE CHECK

- Which of the following can prevent a potential injection attack when building a query from a deserialized JSON object?
  - Using mongo-sanitize to sanitize the data
- True or False: NoSQL databases are NOT susceptible to injection attacks.
  - False

## Managing Third-Party Dependencies

### OVERVIEW

- Dependencies need to be updated due to security risks
- Backwards compatibility and breaking changes are also issues that need to be taken into account.

### UNUSED PACKAGES

- You can use the depcheck tool to determine what dependencies you are relying on that are no longer being used:

`npm install -g depcheck`

- Running this from the project folder location will scan your dependencies and display all of your unused dependencies

### PACKAGE POPULARITY

:::tip
Packages that are not very popular or seldom used should be avoided if possible.
:::

:::warning
If the package is not in common use, it is likely that any security vulnerabilities discovered in it may not get fixed, or may go undiscovered.
:::

### CHECK FOR OUTDATED PACKAGES

- Packages should be updated on a regular basis.
- Dealing with package updates should be part of the normal development lifecycle.
- Packages that are not updated regularly run the risk of keeping the application in a legacy state that will require more effort to update at a later time.
- There is also the danger that a fix for a security vulnerability may not get backported to old versions of a package, leaving your application at risk of attack.
- You can view the outdated packages using npm via the outdated command

```
npm outdated
```

### CHECK FOR OLD PACKAGES

- Packages that haven't been updated in a long time also present a problem.
- It's common for package maintainers to move onto other projects, or simply lose interest in maintaining a package.
- This means maintainers may be slow to add new functionality or fix security issues.
- You can view the last time a package was updated using the `npm view` command.

### CHECK FOR KNOWN VULNERABILITIES

- It's also important to ensure that you are not using any packages that currently have known vulnerabilities in them.
- Npm now does provide built-in functionality to track this type of information:

```
npm audit
```

### RUN A PRIVATE REPOSITORY

- All the packages that npm uses are stored and accessed on the public npm repository.
- This creates a dependency on an external source.
- A package being removed can leave builds in a broken state.
  - For this reason and in order to always be able to produce reproducible builds, it may be advantageous to run a private repository or use a paid plan with npm or a third-party self-hosted solution.

## Node.js Security Assessment

- Which of the following does NOT allow JavaScript to be injected in it?
  - $text operators
- True or False: While SSL has been replaced by TLS, you can still use SSL safely.
  - False
- The principle of least privilege states that:
  - All users or processes should have the least amount of access possible
- True or False: Assigning privileges to a specific position like “Administrator” is known as role-based access control.
  - True
- The node package manager (npm) is NOT able to:
  - Find packages with known vulnerabilities.
- True or False: It can be extremely convenient to run JavaScript expressions using commands, but they also pose a huge security risk.
  - True
- Where should data be validated?
  - Any time data passes a trust boundary
- Which function you can use to determine the last time a package was updated?
  - `npm view`
- Which is the BEST description of authentication?
  - A process that establishes that a user is who they say they are
- Which of the following automatically destroys a session after a specified period of inactivity?
  - Session Timeout
- True or False: It is safe for your content management system to allow users to add snippets of template code and preview it.
  - False
- True or False: Because all data on the client side is untrusted, performing validation on the client side is ineffective.
  - False
- The ability of an attacker to identify whether an account exists is an example of:
  - User account enumeration
- The Secure HTTP cookie flag prevents:
  - The cookie from being sent over plaintext HTTP.
- Using TLS will NOT:
  - Encrypt data at rest.
- Which Pug operator will perform output encoding on user data?
  - The #{} operator
