# sandbox-tls

Sandbox TLS explores the Transport Layer Security (TLS) protocol.

It has a web server with a single endpoint (`/sandboxtls/hello`) that simply returns a string when accessed successfully.

The endpoint will be accessed under three stages of security:
1. No security
2. one-way TLS enabled
3. two-way TLS enabled (aka: mutual TLS or mTLS)

## No security

With no security applied, the client can access the endpoint freely since no authentication or authorization is enforced on either side of the connection.

```yml
# application.yml

server:
  port: 8088
  ssl:
    enabled: false
```

```shell
# Access endpoint using curl

$ curl --verbose --include --request GET http://localhost:8088/sandboxtls/hello
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1:8088...
* Connected to localhost (127.0.0.1) port 8088 (#0)
> GET /sandboxtls/hello HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Content-Type: text/plain
Content-Type: text/plain
< Content-Length: 39
Content-Length: 39

<
* Connection #0 to host localhost left intact
Hello from the Sandbox TLS application.
```

```kotlin
// Access endpoint using Spring WebFlex WebClient

suspend fun testClient() {
    // Prepare client
    val httpClient = HttpClient.create()
    val client = WebClient.builder()
        .baseUrl("http://localhost:8088/sandboxtls")
        .clientConnector(ReactorClientHttpConnector(httpClient))
        .build()

    // Hit server endpoint
    val responseBody = client.get()
        .uri("/hello")
        .retrieve()
        .awaitBody<String>()

    Assert.hasText(responseBody, "'responseBody' must not be empty")

    log.info("Response Body: $responseBody")
}
```

## One-way TLS enabled

One-way TLS secures the server-side of the connection. The server identifies itself and the client verifies its identity through its public/private key pair.

The goals of one-way TLS on the public internet are:
1. To prevent people from visiting spoofed websites.
2. To keep private data secure and encrypted as it travels across a connection.
3. To prevent the data from being altered in transit.

It requires the creation of a keystore that contains a public and private key for the server. The server keeps the private key to itself but shares the public key with its clients. During a client-server connection, the client encrypts its messages using the public key which the server can decrypt using the private key. The server encrypts its messages using the private key which the client decrypts using the public key.

Create a keystore with the `keytool` command list this:

```shell
keytool -v -genkeypair -alias sandboxtls -dname "CN=localhost" \
-keystore server-keystore.p12 -keyalg RSA -keysize 4096 -validity 3650 -keypass secret \
-storetype PKCS12 -storepass secret
Generating 4,096 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 3,650 days
        for: CN=localhost
[Storing server-keystore.p12]
```

Note that `keytool` doesn't support different passwords for key and keystore when the keystore type is `PKCS12`. You'll only get a warning and the keystore will be created successfully. But the passwords will be unexpectedly different and leave you wondering why your connection is failing.

Note also the significance of "CN=localhost". The value specified here is used during peer SSL certificate verification where it should correspond to the hostname used in the URL of the HTTP request. A mismatch causes verification to fail.

You can view the certificate in two ways:

```shell
$ keytool -list -alias sandboxtls -keystore keystore.p12 -storepass secret
sandboxtls, Apr. 28, 2022, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 48:52:98:79:4A:D0:AF:5A:13:9D:94:A5:DD:7F:D6:E0:06:E8:58:FC:29:33:24:57:3B:90:B8:42:B8:07:E0:D3
```

```shell
$ keytool -list -alias sandboxtls -keystore keystore.p12 -storepass secret -rfc
Alias name: sandboxtls
Creation date: Apr. 28, 2022
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
-----BEGIN CERTIFICATE-----
MIIEyzCCArOgAwIBAgIEBNzExzANBgkqhkiG9w0BAQwFADAWMRQwEgYDVQQDEwtT
YW5kYm94IFRMUzAeFw0yMjA0MjgxNTM4MzBaFw0zMjA0MjUxNTM4MzBaMBYxFDAS
BgNVBAMTC1NhbmRib3ggVExTMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAurJOd1wxlPqTsIJRiKOusLkPXK/9bgUp7VwQzNutfzkNWipXxOqonAXEFaVc
9m7V4Uoq+nH3gTJhNaNjmODG1FV6tVZr6SF8zypypvkbjHPFPiTrLilleNrPdYNd
VUnZ7tNbR77iaa6iUdACxeFlvGH50tIkIeltDOneNTG7gUNDoMvexAAjRYYjcEkb
t8uq3Q41pb32O8CNhRYvix4YvaH1ATKHrMOA0W8OfMaJHhz1jlCgjtgF2lqfAN4s
rjkCnTO5o0ZgpudC2vZeN1iF5VYDeEPOswr22sWENVY+ZaciQgwgC82V3POxlxEF
Af7cQrPhIpunq6ozSHtB+XYar07ldOaiBx7yDAWVChUKamPJ/mh7JgoXVclnK+I5
J9xf39nX2B7e8/o+hMZ72W0VV0hQvQLkGT8mAhsm3FxiJrTQK3Us0INZFs/UBeOr
pvhfBhbXS1NXj/gshcRU6fZINxdq0gI1jxZKwJSVstCjLy6NRIejW3lhEgU81TDN
ByM1R9ZQLvMiDNCYv38yiUmURESZe+/1OfctGjth8F4o/qWtkEXZsR1x5+dDTgSx
yeI561WzvUlWEyTeV8D0egHgfI6DQEpVN0tpDlU6JehGVXupB931FpAWHDi38ESZ
pIAgRSLWQvMtkPiQbIW1Ho3FksCMLbVjARd6DKDve2AgbvMCAwEAAaMhMB8wHQYD
VR0OBBYEFDXeUlHONASxFmKtP5EIJZR+8fFJMA0GCSqGSIb3DQEBDAUAA4ICAQCn
orznDzs8y5N3GZwFW5Kf62fXLYGvnyKCabRrx9EjfMjPLzDElwwxLmsEjRkYBwqz
eh7sl7zYpN9FiuA+4I/aSnvfSP0qsRNEqzMU1PvhefD/K0iYDq/QAPf9ZXgDMhBI
TCMtKl/+qnhcQc+SmJxtbR2wSdPG/zILiTWLtGPd1428Ox9/7fLjtsBInmDVEs7b
aQaQtWIbyu9V7509O03QKhWf4ohpIv3oD08w7pi+OimGreOWWpbrNB0E+tXiNC/X
BP25Y45Qcr4ODot3BAnabEYyV9V/DCm8L6TSI/CSf9lwbS8QnL4UtLqyJvHsXeLX
IYklOmuXUjN73uEBffDOFYwWseXAXkGFERj4GEj31Q37bP/O08OIg7YopewM4wv8
E6uDfLCtIuGLSaK3O5JmjPx9D4l2eYPetWSwCrmM5Jx2Nvm04U62N+ioNkSSbL1s
ZKcnFetTTV5+xxUjtjg9hnkBNrKUgpDlaakpyuwzFZPL0dCpiFmVGR/LCclvlrAU
O3AClxNgRWsdO5gixUUkc+Pb92OEHDb+/5ic1UDUAZl8jX9HqlHDPNshukEw4aCx
s8+Ri3tjCAAPwkdMn+XyS1BFLTp2GGly06PcMRjQAe/9l1nT8UCtr5BvQD7II+3x
lgAbTGQAMrnrbUdH9KsjB5S/jycXML3rU6tUMmj/sg==
-----END CERTIFICATE-----
```

Move `server-keystore.p12` to the `src/main/resources` folder.

The Spring Boot server provides helpful TLS-related info if provided this VM argument:

```
-Djavax.net.debug=SSL,keymanager,trustmanager,ssl:handshake
```

This can be used to debug secure connections on both the server and the client side.

```yml
# application.yml

server:
  port: 8088
  ssl:
    enabled: true
    protocol: TLS
    enabled-protocols: TLSv1.2
    key-store: classpath:server-keystore.p12
    key-alias: sandboxtls
    key-password: secret
    key-store-type: PKCS12
    key-store-password: secret
```

```shell
# Access endpoint using curl

$ curl --verbose --include --request GET https://localhost:8088/sandboxtls/hello
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1:8088...
* Connected to localhost (127.0.0.1) port 8088 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS alert, unknown CA (560):
* SSL certificate problem: self signed certificate
* Closing connection 0
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS alert, unknown CA (560):
curl: (60) SSL certificate problem: self signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

The command fails because `curl` performs peer SSL certificate verification by default and it has no way to verify the self-signed certificate provided by the server.

Disable peer verification by providing the option `-k/--insecure`.

```shell
# Access endpoint using curl

$ curl --verbose --include --insecure \
--request GET https://localhost:8088/sandboxtls/hello
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1:8088...
* Connected to localhost (127.0.0.1) port 8088 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=sandboxtls
*  start date: Apr 29 15:02:18 2022 GMT
*  expire date: Apr 26 15:02:18 2032 GMT
*  issuer: CN=sandboxtls
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET /sandboxtls/hello HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.79.1
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Content-Type: text/plain
Content-Type: text/plain
< Content-Length: 39
Content-Length: 39

< 
* Connection #0 to host localhost left intact
Hello from the Sandbox TLS application.
```

Another way to make the command work is to obtain the server certificate itself and tell `curl` to use it to verify the server by providing the option `--cacert`. See instructions further down for how to extract the server certificate from the server keystore.

```shell
# Access endpoint using curl

$ curl --verbose --include --cacert server.cer \
--request GET https://localhost:8088/sandboxtls/hello
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1:8088...
* Connected to localhost (127.0.0.1) port 8088 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: server.cer
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=localhost
*  start date: Apr 29 15:11:16 2022 GMT
*  expire date: Apr 26 15:11:16 2032 GMT
*  common name: localhost (matched)
*  issuer: CN=localhost
*  SSL certificate verify ok.
> GET /sandboxtls/hello HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Content-Type: text/plain
Content-Type: text/plain
< Content-Length: 39
Content-Length: 39

<
* Connection #0 to host localhost left intact
Hello from the Sandbox TLS application.
```

Setting up `WebClient` to perform peer SSL certificate verification requires the creation of a truststore for the client that contains the server certificate.

Export the server certificate like this:

```shell
$ keytool -v -exportcert -alias sandboxtls \
-keystore server-keystore.p12 -storetype PKCS12 -storepass secret -rfc -file server.cer
Certificate stored in file <server.cer>
```

And create the client truststore like this:

```shell
$ keytool -v -importcert -file server.cer -alias sandboxtls \
-keystore client-truststore.p12 -storetype PKCS12 -storepass secret
Owner: CN=localhost
Issuer: CN=localhost
Serial number: 3d11e3a6
Valid from: Fri Apr 29 11:11:16 EDT 2022 until: Mon Apr 26 11:11:16 EDT 2032
Certificate fingerprints:
         SHA1: 0B:CC:FF:E7:30:47:3E:8B:97:72:7A:9E:06:2F:5F:77:C5:95:98:22
         SHA256: 33:9E:D7:05:4C:73:B7:6A:55:D6:87:2E:75:12:BA:E2:E9:54:39:81:30:E9:89:A5:03:56:10:3C:68:28:6C:FE
Signature algorithm name: SHA384withRSA
Subject Public Key Algorithm: 4096-bit RSA key
Version: 3

Extensions: 

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 46 A1 40 B1 B2 44 C1 A2   28 11 73 C8 06 FD F2 30  F.@..D..(.s....0
0010: ED 88 61 3B                                        ..a;
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
[Storing client-truststore.p12]
```

Move `server.cer` and `client-truststore.p12` to the `src/main/resources` folder.

```kotlin
// Access endpoint using Spring WebFlex WebClient

suspend fun connectSecureTLS() {
    log.info("Invoking connectSecureTLS().")

    // Prepare server keystore
    val keyStoreFile = "server-keystore.p12"
    val keyStorePassword = "secret"
    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(ClassPathResource(keyStoreFile).inputStream, keyStorePassword.toCharArray())
    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray())

    // Prepare client truststore
    val trustStoreFile = "client-truststore.p12"
    val trustStorePassword = "secret"
    val trustStore = KeyStore.getInstance("PKCS12")
    trustStore.load(ClassPathResource(trustStoreFile).inputStream, trustStorePassword.toCharArray())
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(trustStore)

    // Prepare SSL provider (client)
    val sslContext = SslContextBuilder.forClient()
        .keyManager(keyManagerFactory)
        .trustManager(trustManagerFactory)
        .protocols("TLSv1.2")
        .build()
    val sslProvider = SslProvider.builder()
        .sslContext(sslContext)
        .build()

    // Prepare HTTP client
    val httpClient = HttpClient.create()
        .secure(sslProvider)
        .keepAlive(false)

    // Prepare WebClient
    val client = WebClient.builder()
        .baseUrl("https://localhost:8088/sandboxtls")
        .clientConnector(ReactorClientHttpConnector(httpClient))
        .build()

    // Hit server endpoint
    val responseBody = client.get()
        .uri("/hello")
        .retrieve()
        .awaitBody<String>()

    Assert.hasText(responseBody, "'responseBody' must not be empty")

    log.info("Response Body: $responseBody")
}
```

## Two-way TLS enabled

Two-way TLS secures both the server-side and the client-side of the connection. Both server and client identifies itself and they verify each other's identity through their public/private key pair.

The client also requires a keystore that contains its public and private key, which is created like this:

```shell
$ keytool -v -genkeypair -alias client -dname "CN=localhost" \
-keystore client-keystore.p12 -keyalg RSA -keysize 4096 -validity 3650 -keypass secret \
-storetype PKCS12 -storepass secret
Generating 4,096 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 3,650 days
	for: CN=localhost
[Storing client-keystore.p12]
```

The server requires a truststore that contains the client certificate.

Export the client certificate like this:

```shell
$ keytool -v -exportcert -alias client \
-keystore client-keystore.p12 -storetype PKCS12 -storepass secret -rfc -file client.cer
Certificate stored in file <client.cer>
```

And create the server truststore like this:

```shell
$ keytool -v -importcert -file client.cer -alias client \
-keystore server-truststore.p12 -storetype PKCS12 -storepass secret
Owner: CN=localhost
Issuer: CN=localhost
Serial number: 680fe7dd
Valid from: Fri Apr 29 13:39:31 EDT 2022 until: Mon Apr 26 13:39:31 EDT 2032
Certificate fingerprints:
	 SHA1: CC:9D:9B:F0:E8:CB:4F:89:AE:43:D7:EA:ED:4F:C4:52:8A:80:B6:12
	 SHA256: 70:2A:0C:16:26:4A:D5:AB:D5:81:F1:44:D6:C8:3C:C9:EC:02:2E:CF:64:51:B6:4B:84:D4:42:90:E6:E3:46:21
Signature algorithm name: SHA384withRSA
Subject Public Key Algorithm: 4096-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 5C D2 6D 28 3C 0A 87 84   69 5A 82 42 EF B4 86 FF  \.m(<...iZ.B....
0010: 04 D9 0B 62                                        ...b
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
[Storing server-truststore.p12]
```

Extract the client private key like this:

```shell
$ openssl pkcs12 -in client-keystore.p12 -nodes -nocerts -out client-key.pem
Enter Import Password: secret
MAC verified OK
```

To make the `curl` command work this time, both the client private key and client certificate must be provided to the server using the option `--key` and `--cert`, respectively.

```yml
# application.yml

server:
  port: 8088
  ssl:
    enabled: true
    protocol: TLS
    enabled-protocols: TLSv1.2
    key-store: classpath:server-keystore.p12
    key-alias: sandboxtls
    key-password: secret
    key-store-type: PKCS12
    key-store-password: secret
    client-auth: need
    trust-store: classpath:server-truststore.p12
    trust-store-type: PKCS12
    trust-store-password: secret
```

```shell
# Access endpoint using curl

$ curl --verbose --include --cacert server.cer \
--key client-key.pem --key-type PEM --cert client.cer \
--request GET https://localhost:8088/sandboxtls/hello
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1:8088...
* Connected to localhost (127.0.0.1) port 8088 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: server.cer
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Request CERT (13):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS handshake, CERT verify (15):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=localhost
*  start date: Apr 29 15:11:16 2022 GMT
*  expire date: Apr 26 15:11:16 2032 GMT
*  common name: localhost (matched)
*  issuer: CN=localhost
*  SSL certificate verify ok.
> GET /sandboxtls/hello HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Content-Type: text/plain
Content-Type: text/plain
< Content-Length: 39
Content-Length: 39

<
* Connection #0 to host localhost left intact
Hello from the Sandbox TLS application
```

```kotlin
// Access endpoint using Spring WebFlex WebClient

suspend fun connectSecureMutualTLS() {
    log.info("Invoking connectSecureMutualTLS().")

    // Prepare server keystore
    val keyStoreFile = "client-keystore.p12"
    val keyStorePassword = "secret"
    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(ClassPathResource(keyStoreFile).inputStream, keyStorePassword.toCharArray())
    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray())

    // Prepare client truststore
    val trustStoreFile = "client-truststore.p12"
    val trustStorePassword = "secret"
    val trustStore = KeyStore.getInstance("PKCS12")
    trustStore.load(ClassPathResource(trustStoreFile).inputStream, trustStorePassword.toCharArray())
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(trustStore)

    // Prepare SSL provider (client)
    val sslContext = SslContextBuilder.forClient()
        .keyManager(keyManagerFactory)
        .trustManager(trustManagerFactory)
        .protocols("TLSv1.2")
        .build()
    val sslProvider = SslProvider.builder()
        .sslContext(sslContext)
        .build()

    // Prepare HTTP client
    val httpClient = HttpClient.create()
        .secure(sslProvider)
        .keepAlive(false)

    // Prepare WebClient
    val client = WebClient.builder()
        .baseUrl("https://localhost:8088/sandboxtls")
        .clientConnector(ReactorClientHttpConnector(httpClient))
        .build()

    // Hit server endpoint
    val responseBody = client.get()
        .uri("/hello")
        .retrieve()
        .awaitBody<String>()

    Assert.hasText(responseBody, "'responseBody' must not be empty")

    log.info("Response Body: $responseBody")
}
```
