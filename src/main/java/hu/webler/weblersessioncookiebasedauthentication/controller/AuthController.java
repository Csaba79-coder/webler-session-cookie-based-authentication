package hu.webler.weblersessioncookiebasedauthentication.controller;

import hu.webler.weblersessioncookiebasedauthentication.config.CookieAuthenticationFilter;
import hu.webler.weblersessioncookiebasedauthentication.entity.User;
import hu.webler.weblersessioncookiebasedauthentication.model.UserLoginRequestModel;
import hu.webler.weblersessioncookiebasedauthentication.persistence.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        if (userRepository.findUserByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exist");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setAuthToken(generateToken());
        userRepository.save(user);
        return ResponseEntity.ok("Registration successful");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(@RequestBody UserLoginRequestModel loginRequest, HttpServletResponse response) {
        Optional<User> optionalUser = userRepository.findUserByUsername(loginRequest.getUsername());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                String token = generateToken();
                Cookie cookie = new Cookie(CookieAuthenticationFilter.COOKIE_NAME, token);
                cookie.setHttpOnly(true);
                cookie.setMaxAge(24 * 60 * 60);
                cookie.setPath("/");
                response.addCookie(cookie);
                user.setAuthToken(token);
                userRepository.save(user);
                return ResponseEntity.ok("Authentication successful");
            } else {
                log.info("Invalid password for user: {}", loginRequest.getUsername());
            }
        } else {
            log.info("User not found: {}", loginRequest.getUsername());
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
    }

    private String generateToken() {
        return UUID.randomUUID().toString();
    }
}
