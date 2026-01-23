package demo.server.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author Fan
 */
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        System.out.println("CustomAuthenticationEntryPoint");

        // 判断请求是否来自浏览器
        boolean isBrowser =
                "GET".equals(request.getMethod())
                        && request.getHeader("Accept") != null
                        && request.getHeader("Accept").contains(MediaType.TEXT_HTML_VALUE);

        String ua = request.getHeader(HttpHeaders.USER_AGENT);
        boolean isBrowser1 =
                ua != null &&
                        (ua.contains("Mozilla")
                                || ua.contains("Chrome")
                                || ua.contains("Safari")
                                || ua.contains("Firefox"));

        String accept = request.getHeader("Accept");
        if (accept == null || accept.trim().isEmpty() || MediaType.TEXT_HTML_VALUE.equals(accept)) {
            System.out.println("text");
        } else {
            System.out.println("json");
        }

//        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
//        if (matcher.matches(request)) {
//            System.out.println("text");
//        } else {
//            System.out.println("json");
//        }

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", authException.getMessage());

        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(authException.getMessage().getBytes(StandardCharsets.UTF_8));

        outputStream.flush();
        outputStream.close();
    }
}
