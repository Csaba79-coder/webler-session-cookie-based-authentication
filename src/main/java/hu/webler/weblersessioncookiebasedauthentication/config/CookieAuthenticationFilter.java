package hu.webler.weblersessioncookiebasedauthentication.config;

import hu.webler.weblersessioncookiebasedauthentication.entity.User;
import hu.webler.weblersessioncookiebasedauthentication.persistence.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CookieAuthenticationFilter extends OncePerRequestFilter {

    public static final String COOKIE_NAME = "auth_by_cookie";

    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Optional<Cookie> cookieAuth = Optional.ofNullable(request.getCookies())
                .flatMap(cookies ->
                    Arrays.stream(cookies)
                            .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                            .findFirst());

        cookieAuth.ifPresent(cookie -> {
            String token = cookie.getValue();
            Optional<User> optionalUser = userRepository.findUserByAuthToken(token);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        });

        filterChain.doFilter(request, response);
    }
}
