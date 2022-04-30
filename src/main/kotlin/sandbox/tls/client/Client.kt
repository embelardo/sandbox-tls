package sandbox.tls.client

import io.netty.handler.ssl.SslContextBuilder
import org.slf4j.LoggerFactory
import org.springframework.core.io.ClassPathResource
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.util.Assert
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import reactor.netty.http.client.HttpClient
import reactor.netty.tcp.SslProvider
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory

private val log = LoggerFactory.getLogger("TestClient")

suspend fun main(args: Array<String>) {
    if (args.isEmpty()) {
        log.info("No arguments found. Defaulting to 'insecure'.")
        connectInsecure()
        return
    }

    when(args[0]) {
        "insecure" -> connectInsecure()
        "securetls" -> connectSecureTLS()
        "securemtls" -> connectSecureMutualTLS()
    }
}


suspend fun connectInsecure() {
    log.info("Invoking connectInsecure().")

    // Prepare HTTP client
    val httpClient = HttpClient.create()
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
