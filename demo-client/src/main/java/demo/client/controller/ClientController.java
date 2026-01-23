package demo.client.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Fan
 */
@RestController
public class ClientController {

    @GetMapping("/api/hello")
    public String hello() {
        return "Hello from ClientController";
    }

    @GetMapping("/test")
    public String test() {
        return "Test from ClientController";
    }
}
