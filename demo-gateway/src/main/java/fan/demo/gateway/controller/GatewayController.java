package fan.demo.gateway.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 *
 * @author Fan
 */
@RestController
public class GatewayController {

    @GetMapping("/api/hello")
    public Mono<String> hello() {
        return Mono.just("Hello from GatewayController");
    }

    @GetMapping("/api1/hello")
    public Mono<String> hello1() {
        return Mono.just("Hello1 from GatewayController");
    }

    @GetMapping("/test")
    public Mono<String> test() {
        return Mono.just("Test from GatewayController");
    }

    @GetMapping("/test/read")
    @PreAuthorize("hasAuthority('fan')")
    public Mono<String> testRead(Authentication authentication) {
        System.out.println(authentication.getAuthorities());
        return Mono.just("Test Read from GatewayController");
    }

    @GetMapping("/test/write")
    @PreAuthorize("hasAuthority('message.write')")
    public String testWrite() {
        return "Test Write from GatewayController";
    }
}
