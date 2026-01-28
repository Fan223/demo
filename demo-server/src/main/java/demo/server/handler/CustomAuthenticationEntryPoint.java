package demo.server.handler;

import fan.fancy.toolkit.http.Response;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author Fan
 */
@Component
@AllArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final JsonMapper jsonMapper;

    private final LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        System.out.println("CustomAuthenticationEntryPoint");
        System.out.println(request.getRequestURL());

        // 判断请求是否来自浏览器
        boolean isBrowser = "GET".equals(request.getMethod())
                && request.getHeader("Accept") != null
                && request.getHeader("Accept").contains(MediaType.TEXT_HTML_VALUE);
        if (isBrowser) {
            System.out.println("text");
//            response.sendRedirect("/login");

            loginUrlAuthenticationEntryPoint.commence(request, response, authException);
        } else {
            System.out.println("json");

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding(StandardCharsets.UTF_8);

            String message = authException.getMessage();
            response.setHeader("WWW-Authenticate", message);

            Response<String> res = Response.fail(message);
            jsonMapper.writeValue(response.getOutputStream(), res);
        }
    }
}
