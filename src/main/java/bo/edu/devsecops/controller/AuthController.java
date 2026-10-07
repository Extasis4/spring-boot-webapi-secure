package bo.edu.devsecops.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final String adminPassword;
    private final String jwtSecret;

    public AuthController(
            @Value("${lab.admin.password}") String adminPassword,
            @Value("${lab.jwt.secret}") String jwtSecret) {
        this.adminPassword = adminPassword;
        this.jwtSecret = jwtSecret;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.getOrDefault("username", "");
        String password = credentials.getOrDefault("password", "");

        LOGGER.info("Intento de acceso para usuario={}", username);

        if ("admin".equals(username) && adminPassword.equals(password)) {
            return ResponseEntity.ok(Map.of(
                    "token", jwtSecret,
                    "message", "Acceso autorizado"));
        }

        return ResponseEntity.status(401)
                .body(Map.of("error", "Credenciales incorrectas"));
    }
}