package fan.demo.gateway.controller;

import fan.fancy.server.resource.starter.reactive.authorize.FancyReactiveAuthorizeCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 *
 * @author Fan
 */
@Configuration
public class TestConfig {

    @Bean
    public FancyReactiveAuthorizeCustomizer reactiveAuthorizeCustomizer() {
        return spec -> spec
                .pathMatchers("/api1/**").permitAll();
    }
}
