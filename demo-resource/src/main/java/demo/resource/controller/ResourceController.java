package demo.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Fan
 */
@RestController
public class ResourceController {

    @GetMapping("/api/hello")
    public String hello() {
        return "Hello from ResourceController";
    }

    @GetMapping("/test")
    public String test() {
        return "Test from ResourceController";
    }

    @GetMapping("/test/read")
    @PreAuthorize("hasAuthority('message.read')")
    public String testRead(Authentication authentication) {
        System.out.println(authentication.getAuthorities());
        return "Test Read from ResourceController";
    }

    @GetMapping("/test/write")
    @PreAuthorize("hasAuthority('message.write')")
    public String testWrite() {
        return "Test Write from ResourceController";
    }
}
