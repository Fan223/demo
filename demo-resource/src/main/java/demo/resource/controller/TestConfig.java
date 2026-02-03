package demo.resource.controller;

import fan.fancy.server.resource.starter.servlet.authorize.FancyAuthorizeCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 *
 * @author Fan
 */
@Configuration
public class TestConfig {

    @Bean
    public FancyAuthorizeCustomizer authorizeCustomizer() {
        return registry -> registry
                .requestMatchers("/api1/**").permitAll();
    }
}
