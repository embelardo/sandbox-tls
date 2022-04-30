package sandbox.tls.controller

import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/sandboxtls")
class Controller {
    @GetMapping("/hello")
    suspend fun hello(): ResponseEntity<String> {
        return ResponseEntity
            .ok()
            .contentType(MediaType.TEXT_PLAIN)
            .body("Hello from the Sandbox TLS application.")
    }
}
