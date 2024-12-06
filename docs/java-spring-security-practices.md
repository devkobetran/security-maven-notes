---
sidebar_position: 2
---

# Java Spring Security

## Securing Spring Applications

### THE SPRING SECURITY FRAMEWORK

- Spring Security offers the necessary building blocks to make it easier to handle authentication and authorization.

### SPRING SECURITY IN VARIOUS APPLICATION TYPES

1. Traditional MVC application
   - A servlet-based controller handles requests and responds with HTML pages, which are rendered in a browser.
2. API-based application
   - A REST-based controller handles a request, and the result is typically JSON or XML data.

## Common Web Vulnerabilities

- Insecure network traffic
- SQL injection
- Cross-site scripting (XSS)

### SERVER-SIDE INJECTION ATTACKS

- **SQL injection** is an example of a **server-side injection attack**
- Spring applications typically use Spring Data, an abstraction layer for database access.
  - Spring Data supports the use of data objects and object repositories.
  - The use of an abstraction layer ensures that the underlying SQL queries are not exposed to the application code.
  - Thus, there is no insecure manipulation of SQL queries to introduce a SQL injection vulnerability.

:::danger

- Native SQL queries are possible to use in Spring Data.
- These code patterns are hazardous and should be avoided if possible. - Example of hazardous code patterns:

      ```js
      // Insecure use of native SQL
      Query sql = entityManager.createNativeQuery("SELECT * FROM users WHERE id = " + id, User.class);
      List results = sql.getResultList();
      ```

      :::tip
      - When avoiding native SQL is not possible, parametrization should be used to avoid SQL injection.
          - Example of secured use of native SQL with parametrization:

          ```js
          // Secured use of native SQL with parametrization
          Query sql = entityManager.createNativeQuery("SELECT * FROM users WHERE id = ?", User.class);
          List results = sql.setParameter(1, id).getResultList();
          ```
      :::

  :::

- Insecure deserialization and vulnerabilities also represent a dangerous attack vector.
  - Example: remote code execution vulnerability in the Spring Messaging library

:::tip

- Fixing vulnerabilities comes down to keeping a project's dependencies up-to-date.

      :::warning
      - While regularly updating dependencies is a good practice, it is insufficient to guarantee the security of an application.
      - The current best practice is to set up continuous monitoring for vulnerabilities in dependencies.
      :::

  :::

:::info
Dependency Monitoring for vulnerabilities tools:

- [Github's dependency graph](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)
- [OWASP's Dependency Track](https://owasp.org/www-project-dependency-track/)
  :::

### CLIENT-SIDE INJECTION ATTACKS

- MVC-based Spring applications generate HTML pages on the server, typically using a template engine.
- The server-side code is responsible for preventing XSS vulnerabilities.

:::danger
Unfortunately, these frameworks are not designed with security in mind.
:::

- API-based Spring applications typically serve JSON or XML data to a frontend application, such as an Angular or React application.
  - The frontend application is responsible for generating pages and rendering data along with preventing XSS vulnerabilities.

#### The Thymeleaf Templating Engine

- Binding variables into templates help prevent a few common XSS vulnerabilities as shown in the example below:

```html
<p th:text="${myData}"></p>
<a th:href="@{${myUrl}}">...</a>
<input type="text" th:value="${myValue}" />
```

:::info

- The `th:text` attribute automatically encodes data for use in an HTML context.
  - Feeding this attribute data containing potentially malicious HTML will not create XSS vulnerabilities.
  - The code in the data will be displayed instead of executed.
- The `th:value` binding encodes the data for use in the context of a value attribute.
  - Again, this behavior prevents XSS vulnerabilities through this data binding.
- The `th:href` data binding is also not vulnerable for payloads that attempt to escape the attribute.
  :::danger - However, Thymeleaf does not automatically prevent the use of potentially dangerous URLs, such as `javascript:alert(1)`. - Here, you remain responsible for ensuring that the value of the `myUrl` variable is safe to use in an href attribute.
  :::
  :::

- Output data containing benign snippets of HTML using `th:utext` binding will directly output HTML, without any protection against XSS attacks.
  - Thus, you need to sanitize the HTML data before putting it on the page.
- Enabling Sanitization for `th:utext` binding example:

```ts
// Sanitize the data to take out dangerous HTML constructs
String myUnsafeData = "<b>Safe</b> <script>console.log('unsafe')</script>";
model.addAttribute("myData", Sanitizers.FORMATTING.sanitize(myUnsafeData));

// Show the safe data in a Thymeleaf template
<p th:utext="${myData}"></p>
```

#### The Freemarker Templating Engine

:::danger - This is an alternative to thymeleaf that offers no protection against XSS attacks.

```html
<p>${myData}</p>
<a href="${myUrl}">This is a link</a>
<input type="text" value="${myValue}" />
```

:::

### Secure Data Transport

- The use of **HTTPS** is crucial to ensure security.
  - This means that all web content and API access should happen over HTTPS.
  - Deploying a Spring application as a WAR file on an application server offloads the responsibility for HTTPS to the application server.
  - Deploying an application behind a proxy makes user-facing HTTPS connections the responsibility of the proxy server.
  - When deploying a Spring Boot application as a standalone application, HTTPS is the responsibility of Spring Boot.
    - Enabling HTTPS can be done through the application.properties configuration file.
    - Doing so requires the configuration of an HTTPS port number, along with the key store containing the keys and certificates.
    - Additionally, the application should define a custom Tomcat connector to redirect all HTTP traffic to HTTPS.
- Example of a Spring application that can ensure that all requests forwarded by the proxy are handled as HTTPS requests:

```ts
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requiresChannel()
            .requestsMatchers(r -> r.getHeader("X-Forwarded-Proto") != null)
            .requiresSecure();
    }
}
```

### Overview of Current Best Practices

:::tip

- Use Spring Data as an abstraction for persistence.
- Avoid the use of native SQL queries, or rely on parametrization when avoiding native SQL is not possible.
- Use Thymeleaf's data binding for variables where HTML output is not needed.
- Rely on a robust sanitization library for all outputs that require benign HTML.
- Deploy HTTPS on your application, either directly or through a proxy.
- Ensure the application is available only over HTTPS by redirecting all HTTP traffic to HTTPS.
  :::

#### Knowledge Check

- Why does a typical Spring application suffer less from SQL injection vulnerabilities?
  - Most Spring applications rely on Spring Data, an abstraction layer that avoids the developer having to write native SQL code.
- True or False: MVC applications built with Spring are automatically protected against XSS.
  - False
- Which of these statements about the Spring Security library is MOST accurate?
  - Spring Security mainly focuses on authentication and authorization.

## Configuring Security Headers

### Introduction

- Browser-based security mechanisms need to be explicitly enabled and configured by the server in order to secure web applications.
  - The server informs the browser of the exact policy configuration through a dedicated response header.

### The Effect of Security Headers

- **X-Content-Type-Options**: By default, browsers try to determine the content type of response by looking at the data.
  - This mechanism is known as content sniffing and can lead to the unintended execution of malicious content.
  - By setting this header to nosniff, the server tells the browser to disable content sniffing.
- **X-Frame-Options**: By default, web pages are free to load arbitrary pages in an iframe.
  - While there are many legitimate scenarios in which this is appropriate, enabling framing can also lead to UI redressing attacks.
  - Therefore, it is recommended to disable framing when possible.
  - This header supports the disabling of framing with the DENY value or restricts it to same-origin framing with the SAMEORIGIN value.
- **Strict-Transport-Security**: When an application runs on HTTPS, the server typically redirects all HTTP traffic to the HTTPS endpoint.
  - However, that redirect might be vulnerable to SSL stripping attacks.
  - By setting a Strict Transport Security policy, the server can inform the browser that it only expects HTTPS traffic.
  - The value of the header contains a max-age parameter.
  - This value defines how long the browser will remember the HTTPS-by-default setting (for example, a year).
  - Additionally, this policy can be applied to all subdomains by setting the includeSubdomains flag.
- **Referrer Policy**: Whenever the browser loads a resource or follows a link, it includes a Referrer header in the request.
  - The value of this header tells the request's receiver where the request originated from.
  - Referrer headers often cause undesired information leakage.
  - By configuring a Referrer-Policy header, the server can alter this default browser behavior.
  - The documentation describes a dozen different types of behavior.
- **Content-Security-Policy**: It offers control over which resources can be loaded, what script code can execute, where outgoing connections can be made, and much more.
  - One exciting aspect of CSP is that it can be deployed in report-only mode.
    - In that case, the browser checks the policy but never blocks an action.
    - The browser will send reports about detected violations to the provided reporting endpoint.
- **Feature Policy**: a relatively new policy, allowing the server to disable certain features in the browser.
  - Doing so prevents third-party content from performing undesired operations.
  - It helps to reduce users' exposure to potentially malicious behavior.

:::danger

- Deprecated headers: - **X-XSS-Protection**: Chrome and Internet Explorer offered built-in protection against reflected XSS attacks. - This header-based policy allows the configuration of that feature. - Due to technical challenges and a limited amount of protection, both browsers have discontinued this mechanism. - Note that Spring Security still sets this header by default, even though it will not affect. - **Public-Key-Pins**: This policy allows the server to provide a set of key pins. - Only these public keys should be accepted to set up an HTTPS connection. - Due to the high potential of misconfigurations, browsers no longer support this feature. - However, a similar key pinning mechanism remains relevant for native and mobile apps.
  :::

### Security Headers in Spring Security

- Security Configuration of header-based policies example:

```ts
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()

        // Specify headers here
        ...
    }
}
```

- Details of security headers in Spring Security, including the default settings and the proper way to configure the security policy:
  - **Cache-Control**:
    - Default Value:
      ```
      Cache-Control: no-cache, no-store, max-age=0, must-revalidate
      Expires: 0
      Pragma: no-cache
      ```
    - Caching is not a browser-based security policy.
    - However, Spring Security disables caching to avoid the leaking of sensitive information through the cache.
    - The default setting is considered to be secure.
    - Spring Security does not offer an API to configure caching.
    - Overriding the default settings requires explicitly setting each of the headers to its desired value.
  - **X-Content-Type-Options**:
    - Default Value:
      ```
      X-Content-Type-Options: nosniff
      ```
    - Spring Security automatically informs the browser to disable content sniffing.
    - Setting this header is a current best practice.
    - There are no other configuration options, so there's also no API available to configure this header.
    - Keep in mind that you should always send the proper Content-Type headers on each response.
  - **X-Frame-Options**:
    - Default value:
      ```
      X-Frame-Options: DENY
      ```
    - By default, framing is denied when Spring Security is enabled.
    - The following code example shows how to change the default value for this header to allow framing from the same origin:
      ```ts
      http.headers().frameOptions().sameOrigin();
      ```
    - When framing of the application is generally allowed, it remains recommended to prevent framing of sensitive pages, such as the login page.
    - The [referenced document](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/headers.html) describes how to build a request matcher for selectively applying a security header.
  - **Strict-Transport-Security**:
    - Default value:
      ```
      Strict-Transport-Security: max-age=31536000 ; includeSubDomains
      ```
    - When the Spring application is running over HTTPS, Spring Security automatically sends an HSTS header.
    - The default value corresponds to current best practices.
    - It sets the expiration time to one year and enables the policy for all subdomains.
    - Example shows how to use the exposed APIs to configure the value of the HSTS header:
      ```ts
      http
        .headers()
        .httpScriptTransportSecurity()
        .maxAgeInSeconds(600)
        .includeSubDomains(false);
      ```
  - **Content-Security-Policy**:
    - Default value: not set
    - By default, Spring Security does not set a CSP policy for the application.
    - The following code example shows how to configure a specific CSP policy:
      ```ts
      String policy = "...";
      http.headers()
          .contentSecurityPolicy("...")
          .reportOnly();
      ```
    - The policy itself is defined as a simple String, containing all the directives with their specific configuration.
    - The last line of the code example illustrates how to apply a report-only policy. For a blocking policy, this method should not be called.
  - **Referrer-Policy**:
    - Default value: not set
    - By default, Spring Security does not configure a referrer policy.
    - The following code example shows how to enable a policy with the current best practice setting.
      - To change this setting, you can select a different value from the `ReferrerPolicy` object.
      - When no value is provided, the configuration defaults to `NO_REFERRER`.
      ```ts
      http
        .headers()
        .referrerPolicy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
      ```
    - Spring Security does not automatically support the other security mechanisms we discussed before.
    - Each of these mechanisms can be configured by explicitly setting the header.
    - The following code example shows how to inject a header into all responses.
      ```ts
      http
        .headers()
        .addHeaderWriter(
          new StaticHeadersWriter("Feature-Policy", "gelocation 'none'")
        );
      ```
    - Finally, you can override all the default headers by turning them off and then reconfiguring each option.
    - The following code example shows how to clear the default values, allowing custom reconfiguration.
      ```ts
      http
        .headers()
        .defaultsDisabled() // remove default values
        .contentTypeOptions()
        .referrerPolicy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
      ```

### Overview of Current Best Practices

- **X-Content-Type-Options**:
  - Best practice for MVC: nosniff
  - Best practice for API: nosniff
  - Requires configuration: no
- **X-Frame-Options**:
  - Best practice for MVC: DENY or SAMEORIGIN
  - Best practice for API: DENY
  - Requires configuration: no
- **HTTP-Strict-Transport-Security**:
  - Best practice for MVC: max-age=31536000 ; includeSubDomains
  - Best practice for API: max-age=31536000 ; includeSubDomains
  - Requires configuration: no
- **Content-Security-Policy**:
  - Best practice for MVC: application-specific
  - Best practice for API: default-src 'none'
  - Requires configuration: yes
- **Referrer-Policy**:
  - Best practice for MVC: strict-origin-when-cross-origin
  - Best practice for API: no-referrer
  - Requires configuration: yes

#### Knowledge Check

- How does Spring Security apply security headers by default?
  - The default configuration applies a static configuration.
- True or False: Spring Security offers an API for most common headers and a non-header-specific configuration mechanism for other headers.
  - True
- True or False: Spring Security automatically applies all security headers supported by the browser.
  - False
    - Additional headers that are more recent or require extensive configuration need to be explicitly configured by the developer.

## User Authentication with Spring

### User Authentication

- Verifying the user's identity is done during authentication.

### Handling User Authentication in Spring

- When a project includes Spring Security as a dependency, the form-based login page is enabled by default.
  - The login page asks for a username and password, which is verified against the application's user database.
  - If the credentials are considered to be valid, the application keeps track of the authentication state, along with the associated permissions.
  - Spring will verify the authentication status and permissions on all endpoints with a specific authorization configuration.
- Behind the scenes, Spring uses an internal service to verify the user's credentials.
  1. One service is the password encoder and verification service
  2. Second service is the one that retrieves the user's details.
- The following code example shows how to modify the endpoint where the login page is located. It also illustrates how to inform Spring where to find the user information.

```ts
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Allow access to some pages without authentication,
        // but require authentication for the rest
        http
        .authorizeRequests()
            .antMatchers("/", "/public", "/login").permitAll()
            .anyRequest().authenticated()
            .and()
        // Configure the login page
        .formLogin()
        .loginPage("/signin");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        //configure the authentication provider (in memory as a demo only)
        auth
            .inMemoryAuthentication()
            .withUser("admin")
            .password(encoder.encode("test"))
            .roles("ADMIN");
    }
}
```

### Using the "Remember Me" Feature

- By default, the duration of an authenticated session is tied to the lifetime of the Spring session object.
- However, some non-sensitive applications might want to prolong the user's authentication state.
  - That's where the "Remember Me" feature comes into play.
- Spring Security has built-in support for the "Remember Me" feature.
  - The following code example shows how to enable the feature:
  ```ts
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http
      .authorizeRequests()
          .antMatchers("/", "/public", "/login").permitAll()
          .anyRequest().authenticated()
          .and()
      .formLogin();
      .and()
      .rememberMe().key("MySecretValue"); //Enabling this automatically adds a checkbox to the login form
  }
  ```
- By configuring the "Remember Me" feature, a checkbox will automatically appear on the login page.
  - When the user ticks this checkbox, a cookie with an authentication token will be stored in the user's browser.
  - The cookie is linked to the username, the expiration time of the token, and the user's password.
    :::note
  - The secret key provided in the code example protects the authentication token against tampering.
  - Spring Security handles all of this.
    :::
- When the user changes their password, all existing "Remember Me" tokens automatically become invalid.
- Since the password is only used as input for a keyed hash, it is not subject to offline brute-forcing attacks.

:::warning

- The secret value in the code example here is a hardcoded string.
- In practice, this secret should be retrieved from a dedicated vault service
  :::

### Common Attacks against Authentication Forms

Three frequent attacks against authentication forms:

1. **Brute Force Logins**: A brute force login attempt is when an attacker tries various passwords for a user account, hoping to get lucky.
   - Attackers use lists of previously stolen passwords to make their attack more successful.
   - By default, the Spring Security authentication form does not provide built-in brute force protection.
   - However, Spring exposes an `AuthenticationFailureBadCredentialsEvent`, which indicates that a failed login attempt just happened.
   - By hooking into this event with an `AuthenticationFailureEventListener`, the application can keep track of failed login attempts.
   - Once a certain threshold for a user is reached, the application can decide to reject further attempts for this particular account.
   - Rejecting a login attempt can be done by throwing an exception in the `UserDetailsService`.
2. **Account Enumeration Attacks**: the attacker learns whether a particular user account exists in the system.
   - With that information, the attacker can focus on a brute force attack on those accounts that are known to exist in the system.
   - Enumeration attacks are possible when the authentication procedure behaves differently for failed authentication attempts with accounts that exist, compared to attempts with accounts that do not exist.
   - The error message on the login page does not reveal the reason for a failed authentication attempt.
   - However, when an account is not found, the login endpoint immediately returns with an error.
   - When the user account exists, but the password is wrong, the operation takes significantly longer when verifying the password.
   - Such an attack is known as a timing-based enumeration attack.
     :::warning
     There is no straightforward way to prevent such an attack in Spring Security.
     :::
3. **Credential Stuffing**: a particular type of brute force attack.
   - The attacker tries to log in with a stolen username and password combination.
   - Credential stuffing is unique because an attacker typically only tries one combination per account for a large number of accounts.
     :::warning
   - Countering credential stuffing is quite challenging.
   - One way would be to use a global brute force protection mechanism, which monitors failed login attempts for all accounts.
   - However, locking out all accounts would also be a drastic countermeasure.
     :::

### Overview of Best Practices

- The current best practice is to rely on external authentication services.
  - The best way to do that is by using OpenID Connect

#### Knowledge Check

- True or False: The current best practice is to rely on Spring Security to provide a secure form-based authentication mechanism.
  - False
- Which of these attacks against the authentication form is stopped by Spring Security?
  - None of these (Brute Force Attacks, Enumeration Attacks, and Credential Stuffing)
- Which of these statements about user authentication is MOST accurate?
  - User authentication is so complicated that it is recommended to use OpenID Connect to offload authentication.

## Secure Password Storage

### Password Storage Best Practices

:::danger
Insecure Legacy password storage mechanisms include: - Simple hashing function without a salt such as SHA1 are easy to reverse using precomputed rainbow tables. - Plaintext passwords are easy to abuse when an attacker gains access to the database. - Hashes with a salt are still vulnerable to brute force attacks, where dedicated password cracking rigs calculate billions of hashes per second.
:::

- The current best practice for storing passwords is using a dedicated password storage function.
  - Examples: bcrypt, scrypt, and Argon2.
- These functions are designed to use a salt by default, and they have a configurable cost factor.
  - By tweaking the cost factor, the developer can make the hash calculation as expensive as tolerable.
  - Doing so ensures that large-scale brute force attacks become impossible.
  - Instead of billions of calculations per second, a similar machine would only be able to attempt hundreds of combinations per second.

### Storing Passwords with Spring Security

- A set of password encoders handles password encoding in Spring Security.
  - The `BCryptPasswordEncoder` class supports the bcrypt algorithm.
  - The `SCryptPasswordEncoder` supports scrypt through the BouncyCastle library.
    :::warning
    Unfortunately, the SCryptPasswordEncoder only provides a partial implementation of the algorithm, making it less useful.
    :::
- The `BCryptPasswordEncoder` can be configured with a cost factor.

:::tip

- The current best practice is a cost factor of 13.
- However, it is recommended to set this as high as possible.
- To find out a good value for the cost factor, try running a code snippet using the `BCryptPasswordEncoder` with a cost factor of 13 or more.
- A proper setting is a factor that makes the hashing operation last about 150 to 200 milliseconds.
- Note that the cost factor is an exponent, so increasing it by one already has a significant impact on the execution time.
  :::

:::danger
By default, Spring Security uses a cost factor of 10.
:::

:::info

- The following code snippet shows how to reinitialize the default password encoder to use a cost factor of 13.

```ts
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(13);
}
```

- When authentication is enabled in combination with the UserDetailsService, Spring will automatically use this configured password encoder to verify and encode passwords.

:::

### Supporting Multiple Password Storage Mechanisms

- Since version 5.1, Spring Security supports the automatic migration of stored password hashes when using the UserDetailsService.
- To enable the automatic migration, the application needs to define a delegating password encoder.
- Such an encoder is a wrapper around multiple individual password encoders.
- When a password needs to be matched against a hash, the delegating password encoder will ensure that the right encoder is used.
- When it notices that the actual encoder is not the default encoder, this mechanism will automatically migrate the hash stored in the UserDetailsService.
- The following code snippet shows how to set up a delegating password encoder.

  - In this example, we configure bcrypt with a cost factor of 13 as the default.
  - We also configure a simple hash-based encoder to handle the old hashes that are still stored in the database.
  - This encoder supports authenticating both users with old and new password hashes.
  - The `idForEncode` value indicates the preferred password encoder that should be used to encode passwords.
  - Under the hood, Spring Security stores hashes in the following format: `{id}hash`.
  - The ID part of this data structure identifies the algorithm, which allows the selection of the correct password encoder.
  - Spring Security defines default IDs for the built-in password encoders, but the ID is fully customizable for custom encoders.

  ```ts
  @Bean
  public PasswordEncoder passwordEncoder() {
      // Create a map of encoders
      final Map<String, PasswordEncoder> encoders = new HashMap<>();
      encoders.put("bcrypt", new BCryptPasswordEncoder(13));
      encoders.put("sha256", new StandardPasswordEncoder());

      // Set up the delegating password encoder
      String idForEncode = "bcrypt";
      return new DelegatingPasswordEncoder(idForEncode, encoders);
  }
  ```

- The following example shows how to define two BCryptPasswordEncoder objects with different cost factors.
  - Such a delegating password encoder provides an easy way to increase the cost of the hashing function over time.

```ts
@Bean
public PasswordEncoder passwordEncoder() {
    // Define two bcrypt encoders
    BCryptPasswordEncoder bcrypt13 = new BCryptPasswordEncoder(13);
    BCryptPasswordEncoder bcrypt10 = new BCryptPasswordEncoder(10);

    // Create a map of encoders
    final Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("bcrypt10", bcrypt10);
    encoders.put("bcrypt13", bcrypt13);

    // Set up the delegating password encoder
    String idForEncode = "bcrypt13";
    return new DelegatingPasswordEncoder(idForEncode, encoders);
}

```

### Overview of Current Best Practices

- Bcrypt is the recommended algorithm, as it is the only algorithm that is fully supported by Spring Security.
- The cost factor for using bcrypt should be set to 13 or higher if the server can handle that load.
- When dealing with legacy password hashes, a delegating password encoder can be used to upgrade hashes gradually.
- It is highly recommended to hook Spring Security's password encoder into the UserDetailsService to enable automatic migration of passwords.

#### Knowledge Check

- What is the difference between a password encoder and a delegating password encoder in Spring Security?
  - A password encoder supports a single algorithm, while a delegating password encoder supports multiple algorithms by wrapping multiple encoders.
- Which of these algorithms is NOT an acceptable choice for hashing passwords?
  - SHA-256
- True or False: When a strong password hashing mechanism is configured as the default option in a delegating password encoder, Spring Security automatically upgrades weak hashes through the UserDetailsService.
  - True
  - Note: Since version 5.1, Spring Security automatically migrates hashes that have not been encoded with the default algorithm. This mechanism is useful to upgrade legacy hashes to modern hashes when the user authenticates.

## Authentication with OpenID Connect

### Why Using OpenID Connect?

- OpenID Connect (OIDC) is an authentication protocol built on top of OAuth 2.0.
- Its purpose is to enable a federated identity mechanism through a centralized provider.
- The OpenID provider is responsible for authenticating the end user.
- The provider relays that authentication information to the application that requests it.
- OIDC is an effective protocol for offloading authentication.

### Background on OpenID Connect

- We have a backend application that wants to receive authentication information about the user.
  - Our backend application becomes the OIDC client application.
  - The backend initializes an OIDC flow involving a centralized identity provider.
  - Such a provider can be a public third-party provider, such as Google or Github, or a private provider for a particular company.
  - When the OIDC flow completes, the application receives an identity token.
  - The name of this token is rather misleading, as it does not contain information about the user's identity.
  - Instead, it contains a set of claims about the user's authentication with the identity provider.
  - The identity token is a **JSON Web Token (JWT)**.
  - The identity provider signs the identity token to ensure its integrity.
  - The token contains claims about the user's authentication.
  - One of these claims is the sub claim, which contains the user's unique identifier within the provider's realm.
  - With this identifier, the application can use the identifier to look up the correct user within the application's database.

### Integrating OpenID Connect in Spring

- The configuration settings for OIDC include the client ID and client secret as given to your application by the identity provider.
- Additional settings can be the requested scopes, the endpoints at the provider, and so on. Since this configuration is highly dependent on the provider.
- Once the provider is configured correctly, the application can enable OIDC-based login. Example:

```ts
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .oauth2Login();
    }
}
```

### Overview of Current Best Practices

- The best practice for implementing authentication in a modern Spring application is using OpenID Connect.
- Doing so allows the offloading of authentication to a dedicated, centralized provider.
- Given this best practice, recent versions of Spring Security come with built-in support for OpenID Connect.

#### Knowledge Check

- True or False: The application requesting authentication receives an identity token, which contains information about the authentication of the end user.
  - True
- How does the backend application link the authenticated user to a meaningful user in the application?
  - Using the unique identifier included in the identity token.
- Which of these statements about OpenID Connect is MOST accurate?
  - OpenID Connect supports the offloading of user authentication to an identity provider.

## Implementing an Authorization Framework

### Access Control Models

- Web application frameworks have built-in support for user roles and RBAC.
- Roles are an intuitive way to represent the permissions of a user.
  - Roles in an application typically match the user's responsibilities within an organization.

:::warning
Modern systems are moving away from checking roles on specific operations.
:::

- Instead, they are checking if a user has specific permissions.
  - Instead of checking the presence of a specific role, the system would check the presence of the specific permission.
  - From a developer's point-of-view, the system has become a lot more flexible.
- **Attribute-based access control (ABAC)** goes even further than checking specific permissions.
  - Also, checks whether the attributes of an operation are valid.
  - Attributes can be anything, including the type of operation, the object for which the operation is executed, the user's account, and even environment properties such as system time or user location.
  - ABAC is more flexible than RBAC or a permission-based system.
  - However, designing and managing the attributes for ABAC is quite challenging.

:::note
Most systems today can implement a robust authorization system using a permission-based system, typically in combination with RBAC.
:::

### Leveraging Spring Security for Authorization

- A first core concept in the Spring Security authorization system is a role, which can be assigned to a user.
- A second core concept is authority.
  - Authorities are also granted to users and are very similar to roles.
  - Authorities can be anything you want them to be, usually high-level concepts.
  - Authorities can be used to build a custom authorization system.
  - Example: an authority called `DEPARTMENT`, representing the ability to access departmental data
- Example implement an authorization policy with Spring Security:
  - You can see a global HTTP configuration rule for the entire application.
  - The rule is associated with a matcher that applies to the /pos/sale endpoint.

```ts
http
  .authorizeRequests()
  .antMatchers("/pos/sale")
  .hasAnyRole("CASHIER", "DEPHEAD", "STOREMGR");
```

- The second option offers more flexibility.
  - Through PreAuthorize annotations, Spring Security allows us to define our policy on each of the API endpoints.
  - This way, we have the policy close to the actual code, making it easier to write and maintain the policy.
  - We are using roles, requiring us to implement an elaborate check.
  - Example:

```ts
@PreAuthorize("hasRole('CASHIER') or hasRole('DEPHEAD') or hasRole('STOREMGR')")
@RequestMapping(path = "/pos/sale", method = RequestMethod.POST)
public ResponseEntity<Object> createSale(HttpServletRequest request){
    ...
}
```

- Example of using Authority:
  - Using authorities makes it easier to define authorization policies.

```ts
http.authorizeRequests()
    .antMatchers("/dept/statistics").hasAuthority"Department");
```

- To build a more flexible and customizable authorization system, Spring Security supports the use of permission-based expressions.
  - We rely on a PermissionEvaluator to check if the user has the proper permission.
  - Example:

```ts
@PreAuthorize("hasPermission(null, 'SALE_CREATE')")
@RequestMapping(path = "/pos/sale", method = RequestMethod.POST)
public ResponseEntity<Object> createSale(HttpServletRequest request){
    ...
}
```

- How to set up a customer PermissionEvaluator:
  - Apart from the PreAuthorize annotation, Spring Security also provides a PostAuthorize annotation.
  - That annotation can be used to make access control decisions on the result of a method call

```ts
@Configuration
public class PermissionConfig {
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(new PermissionEvaluator() {
            @Override
            public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission){
                boolean result = false;

                if(permission.equals("SALE_CREATE")){
                    ...
                }
                else {
                    ...
                }
                return result;
            }

            @Override
            public boolean hasPermission(Authentication authentication, Serializable targetId, string targetType, Object permission){
                ...
            }
        });
        return handler;
    }
}
```

- To enforce the PreAuthorize and PostAuthorize annotations, the application needs to add the following annotation to its security configuration.

```ts
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

### Avoiding Common Authorization Vulnerabilities

- A crucial step in an authorization policy is the proper enforcement of authorization at the API endpoints.
  - To achieve this authorization check, the application can rely on the PreAuthorize annotations that check for the proper set of permissions.
  - The set of permissions should consist of all permissions needed to complete the operations performed by this endpoint.
- Fine-grained operation-level permissions
  - Each of the operations on the service layer should use PreAuthorize and PostAuthorize annotations to double-check permissions.
  - Doing so ensures that a mistake in the authorization policy on the endpoint level cannot easily be exploited.

:::info

- To recap, the proposed defense-in-depth authorization strategy enforces authorization checks on three levels: 1. A role check on the global API level 2. Permission checks for each API endpoint 3. Permission checks for each operation as a fallback mechanism
  :::

### Overview of Current Best Practices

- 5 Guidelines:
  1. Permissions should be implemented close to the actual endpoint. Doing so increases the maintainability and auditability of the authorization policy.
  2. The actual authorization decisions should be made in central policy implementation. Endpoint-level checks ask for specific permissions, but a central policy verifies whether the user has those permissions.
  3. To ensure that a mistake in the endpoint-level policy does not automatically result in a security vulnerability, use a defense-in-depth authorization strategy. Augment endpoint-level checks with API-level checks and operation-level checks.
  4. Authorization policies need to be regularly audited to ensure they enforce the correct decisions. If possible, consider writing an extensive authorization test suite to automate this process.
  5. Closely monitor the authorization policy. Each authorization decision taken by the system should be logged. If desired, the system should also act upon unexpected authorization failures.

#### Knowledge Check

- Which of these statements about role-based access control (RBAC) is MOST accurate?
  - RBAC is still quite common, especially in combination with endpoint-level permission checks.
- Which of the following statements is NOT part of the current best practice for implementing a robust authorization policy?
  - Relying on if-else code constructs to verify the necessary permissions.
- True or False: Spring Security does NOT differentiate between roles and permissions.
  - False

## Advanced Authorization Scenarios

### API Authorization with OAuth 2.0

- When a user authenticates, Spring keeps track of the user's authentication state, offering the ability to make decisions based on a user's role or authority.
- In an architecture using OAuth 2.0, the API becomes a resource server.
  - The application calling the API acts on behalf of the user when calling the API.
  - To convey that authority, the application has obtained an access token from the authorization server.
- In a WebSecurityConfigurerAdapter,
  1. Define a JWT decoder, which will verify and decode the incoming JWT access token
  2. Define an authorization policy and initialize the OAuth 2.0-specific behavior in the configure method.

```ts
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${application.audience}")
    private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoderJwtSupport jwtDecoder = (NimbusJwtDecoderJwtSupport)
            JwtDecoders.fromOidIssuerLocation(issuer);

        OAuth2TokenValidator<Jwt> audienceValidator = new TokenValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return jwtDecoder;
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security.httpBasic().disable();
        security.authorizeRequests()
            .mvcMatchers("/public").permitAll()
            .mvcMatchers("/private").hasAuthority("SCOPE_reviews:read")
        .and()
        .oauth2ResourceServer().jwt();
    }
}
```

- While the issuer check is provided by default, the audience check requires a custom validator.

```ts
class TokenValidator implements OAuth2TokenValidator<Jwt> {
    private final String audience;

    TokenValidator(String audience) {
        this.audience = audience;
    }

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        System.out.println("Running token validator function ...");
        OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);

        if(jwt.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(error);
    }
}
```

### Implementing a CORS Policy

- Cross-origin resource sharing (CORS) comes into play when a browsing context sends a request to a backend.
  - If that request is sent across origins, the browser enforces a CORS policy to ensure that the backend intended such cross-origin access.
  - If the browser is not convinced that is the case, it will either prevent the sending of the request or deny the reading of the response.
- If the API needs to be accessed across different origins, it needs to configure a proper CORS policy.
  - By default, cross-origin requests are not allowed, so an explicit CORS policy needs to be defined.
  - When a policy is defined, unauthorized cross-origin requests will result in a response with status code 403 (Forbidden).
  - Cross-origin requests that are allowed by the policy will be processed, and the proper response headers will be added.
- Configuring CORS in Spring-based applications has 3 implementation strategies:

  1. **A Centralized CORS Policy**: recommended when all API endpoints share a single CORS policy.

     - Example:

     ```ts
     @Configuration
     @EnableWebMvc
     public class WebConfig implements WebMvcConfigurer {

         @Override
         public void addCorsMappings(CorsRegistry registry) {
             registry.addMapping("/**").allowedOrigins("https://example.com");
         }
     }
     ```

  2. **Controller-Specific CORS Policies**: configure a CORS policy for a particular controller by adding the `@CrossOrigin(origins = {"https://example.com"})` annotation.
     - Doing so configures the defined CORS policy for all endpoints of this controller.
     - Example:

  ```ts
  @Controller
  @RequestMapping("/api")
  @CrossOrigin(origins = {"https://example.com"})
  public class MyController {
      ...
  }
  ```

  3. **Method-Specific CORS Policies**: uses annotations to define the CORS policy but applies them to individual endpoints.
     - The first endpoint allows cross-origin access from one origin, while the second does not allow any cross-origin access.
     - Example:

  ```ts
  @RequestMapping(path = "/one")
  @CrossOrigin(origins = {"https://example.com"})
  public ResponseEntity<Object> one(HttpServletRequest request) {
      ...
  }

  @RequestMapping(path = "/two")
  public ResponseEntity<Object> get2(HttpServletRequest request) {
      ...
  }
  ```

### Securely Exposing Websockets

- REST APIs are used by both web and mobile clients to interact with backend systems.
- Complementary to traditional HTTP requests and responses, modern browsers also support Websockets.
- Websockets use HTTP to bootstrap a low-level socket connection between browser and server.
- That socket connection provides a duplex binary communication channel, enabling high-volume continuous traffic streams.
- When exposing a Websocket endpoint, two essential security considerations come into play:
  1. The application needs to ensure that the Websocket is exposed only to legitimate users.
     - Needs to enforce a proper authorization decision before opening a socket connection.
  2. The application needs to ensure that the connection is being opened by a browsing context with the proper origin.
     - Otherwise, the application could suffer from an attack known as cross-site Websocket hijacking.
- Because Spring Messaging is fully integrated into the Spring framework, enforcing authorization decisions on Websocket connections is possible by implementing an AbstractSecurityWebSocketMessageBrokerConfigurer class.
  - Example shows how to ensure that a user is authenticated before the socket connection is established:
  ```ts
  @Override
  protected void configureInbound(
      MessageSecurityMetadataSourceRegistry messages) {
          messages
              .simpDestMatchers("/socket/**").authenticated()
              .anyMessage().authenticated();
      }
  ```
- When registering a Websocket through Spring Messaging, the application can provide a list of allowed origins.
  - Example shows how to do that for a single origin:

```ts
@Override
public void registerStompEndpoints(StompEndpointRegistry registry){
    registry.addEndpoint("/socket")
        .setAllowedOrigins("https://example.com")
        .withSockJs();
}
```

### Overview of Current Best Practices

1. Strictly configure advanced authorization scenarios to allow only the access that is needed by the client and nothing more.
   - This includes refusing invalid access tokens, rejecting invalid origins, and not exposing Websockets to unauthenticated users or unexpected origins.
2. The security behavior of each of these scenarios must be thoroughly tested.
   - By writing security test cases, you can verify the application's behavior.

#### Knowledge Check

- True or False: When switching from internal user management to using OAuth 2.0, you must rewrite the application's entire authorization stack.
  - False
  - Note: Spring Security supports the use of authorities, which can be mapped to OAuth 2.0's scopes. As long as the application sticks to the Spring Security way of implementing authorization, traditional authorization and OAuth 2.0-based authorization should be interchangeable.
- Which of these mechanisms is NOT a recommended way to configure a CORS policy in a Spring application?
  - Setting the CORS header programmatically on the response object.
- What is the most straightforward way for a Spring application to enforce role-based authorization decisions on WebSocket connections?
  - By using Spring Messaging in combination with the built-in authorization logic.

## Managing Secrets in Your Application

### The Need for Secrets Management

- A secret is a set of credentials to connect to the database.
  - Example: API keys, cryptographic key material, and OAuth 2.0 client credentials
  - These secrets are extremely sensitive, as they allow the holder to impersonate the application.
  - Configuration files are not secured.
  - Plenty of system breaches happen when a developer accidentally publishes a configuration file in a public code repository.

### The Benefits of Centralized Secret Storage

- Secret management system (aka a vault) is a service responsible for managing application secrets.
  - Each application connects to the vault and receives the necessary secrets from that vault.
  - Vault systems are also designed to handle cryptographic key material, along with performing operations using these cryptographic keys.
  - As a result, clients often do not need to handle any cryptographic keys themselves.
- The vault offers strict access control over which clients are allowed to access which secrets.
  - A vault also makes managing and changing secrets a lot easier and provides a centralized service, which is beneficial for auditing purposes.
- When the application authenticates itself to the vault, it needs a token.
  - To get that token, the application is supposed to first authenticate itself with the vault.
  - Authentication typically relies on a client identifier and a client secret.
  - With those credentials, the client can get a fresh token.
  - With that token, the client can get the necessary secrets to operate.
- The client credentials for authenticating to the vault are known as "secret zero."

### Using Spring Vault in Practice

- **HashiCorp's Vault**: runs as a standalone service, exposing its interface through a web-based GUI, an HTTP API, and a CLI.

:::info
The Spring framework offers support to integrate HashiCorp's vault directly into Spring with the Spring Vault library.
:::

- HashiCorp's vault is capable of generating database credentials.
  - It does so by creating a new account in the database with predefined permissions.
  - It then provides the credentials for that account to the application.
  - The application can use these credentials as long as they are valid.
  - secret listener in the Spring Vault project will notice when the credentials are about to expire and trigger the vault to generate new ones.
- While vault-based database access can be highly automated, some scenarios require programmatic access to certain secrets.
  - Setting up Spring Vault for such access is not that complicated.
  - Once the Spring Vault dependency is added, the application can initialize the vault by providing an implementation for AbstractVaultConfiguration.

```ts
@Configuration
public class VaultConfig extends AbstractVaultConfiguration {
    @Override
    public ClientAuthentication clientAuthentication() {
        // Obtain the token through configuration or by
        // authenticating using the client credentials
        return new TokenAuthenticator("...");
    }

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.create("localhost", 8200);
    }
}
```

- Once loaded, Spring components can access the vault by auto-wiring the VaultOperations object.
  - Example shows how to use the vault to initialize the key for the "Remember Me" feature.
  - For the "Remember Me" feature, the secret is stored as a simple "key-value" pair in the vault. Such a secret has no expiration date, but it remains recommended to rotate the "Remember Me" secret regularly.

```ts
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    VaultOperations vaultOperations;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        VaultResponse response = vaultOperations.read("secret/data/remember");
        // Get the data (if multiple values are present, the right one should be extracted)
        Spring secret = response.getData().get("data").toString();

        http
            .formLogin()
            .and()
            .rememberMe().key(secret);
    }
}
```

### Overview of Current Best Practices

- The current best practice is to deploy a dedicated secrets management system. HashiCorp's vault is a good example.
- The Spring framework offers support for integrating a vault through the Spring Vault library.

#### Knowledge Check

- True or False: Vaults offer support for various types of secrets, including database credentials and "key-value"-based secrets.
  - True
- What is "secret zero"?
  - The client's credentials to authenticate to the vault
- Which of these statements about Spring Vault is MOST accurate?
  - Spring vault is a library to integrate HashiCorp's vault into a Spring application.

## Conclusion (Spring Security)

### Overview of Current Best Practices

- **Integrate Spring Security**
  - All Spring applications should integrate Spring Security as a dependency.
  - It is recommended that you refine the security configuration further.
- **MVC-based Spring Applications**
  - MVC-based Spring applications still suffer from cross-site scripting (XSS) vulnerabilities.
    - Two crucial defenses are context-sensitive output encoding and sanitization.
- **Authentication and Authorization**
  - Both are well-supported by Spring Security.
  - Spring Security offers support for in-application authentication, but also supports the more modern OpenID Connect protocol.
  - Authorization can be implemented within the application or can be achieved using OAuth 2.0 access tokens.
- **Spring Vault**
  - Your application should rely on a vault to manage its secrets.
  - Spring Vault offers a straightforward way to integrate HashiCorp's vault into your application.

#### Knowledge Check

- Which of these vulnerabilities is NOT handled by Spring Security at all?
  - Preventing XSS vulnerabilities in the application's user interface
- Which of these statements about Spring Security is true?
  - Using Spring Security as intended improves maintainability and updatability over time.
- True or False: Without Spring Security, building secure applications is NOT possible.
  - False

## Java Spring Security Assessment

- What type of secrets can be stored in a vault?
  - All secrets listed here
- True or False: Using OpenID Connect with Spring Security only requires the configuration and enabling of the feature, nothing more.
  - True
- Which of the features below is one of the strengths of Spring Security?
  - Advanced Authentication and authorization
- True or False: Spring Security supports centralized code-based configuration and local annotation-based configuration for most features.
  - True
- True or False: WebSocket connections require separate authorization logic to determine the permissions of the user and the source origins of the connection.
  - True
- How would a developer prevent attacks against the authentication form in a Spring application?
  - By implementing custom code to detect malicious behavior based on authentication failures
- Which service is instrumental to automatically update weakly stored passwords?
  - UserDetailsService
- In a textbook credential stuffing attack, how many times does an attacker try to authenticate to an account?
  - Only once
- True or False: Using different password encoding strategies within a single application is straightforward with using Spring Security.
  - True
- What is the major benefit of having the user's password as input to generate the "Remember Me" token?
  - It ensures the token becomes invalid when the user changes their password
- True or False: When using Spring Security, there is no way to override the default header configuration.
  - False
- How does a Spring application configure the proper security headers?
  - Through a centralized security configuration class
- Which of these statements is most accurate?
  - OpenID Connect is an authentication protocol
- True or False: Spring Security is a good library to mitigate traditional OWASP top 10 injection issues.
  - False
- Which of these options is not a valid CORS configuration strategy in Spring applications?
  - A centralized policy using path-based annotations
- True or False: Using Spring Vault makes it easy to auto-wire a vault service into the application.
  - True
- Why is the dependency management crucial for Spring applications?
  - Because a vulnerability in a dependency creates a vulnerability in the application
- What is an identity token?
  - A token representing the user's authentication with an identity provider.
- What is the purpose of the custom JWT decoder when using OAuth 2.0 with Spring applications?
  - To ensure the issuer and audience of the JWT are valid
- Which of these authorization concepts can be fully customized?
  - Permissions
- True or False: Security headers need to be applied by both MVC-based applications and API-based applications.
  - True
- True or False: Spring Security offers password encoders, but none of the available algorithms corresponds to current best practices.
  - False
- Which of these comparisons between hardcoded secrets and a secret stored in a vault makes sense?
  - Secrets stored in a vault can be subjected to access control policies, which is much harder with hardcoded secrets
- Which of these permission models is the default option used in Spring Security?
  - Role-based access control (RBAC)
- Which feature of Spring Security is not a recommended best practice for modern web applications?
  - The implementation of form-based user authentication
- True or False: Role-based access control (RBAC) is more flexible than attribute-based access control (ABAC).
  - False
- True or False: Spring applications do not suffer from SQL injection, as they typically rely on Spring Data for database access.
  - False
