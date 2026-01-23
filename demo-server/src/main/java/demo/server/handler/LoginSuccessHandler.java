package demo.server.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author Fan
 */
@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("LoginSuccessHandler: {}", authentication.getPrincipal());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(authentication.getPrincipal().toString().getBytes(StandardCharsets.UTF_8));

        outputStream.flush();
        outputStream.close();
    }
}
