package demo.server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Fan
 */
@RestController
public class ServerController {

    @GetMapping("/api/getCaptcha")
    public String getCaptcha() {
        return "qwer";
    }

    @GetMapping("/test")
    public String test() {
        return "Test from ServerController";
    }
}
