package com.example.auth.controller;

import com.example.auth.model.*;
import com.example.auth.repository.UserRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    private final Map<String, Token> tokens = new ConcurrentHashMap<>();
    private final int tokenMinutes = 15;

    public AuthController(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @PostMapping("/register")
    public String register(@RequestParam String login,
                           @RequestParam String email,
                           @RequestParam String password,
                           @RequestParam(required = false) Set<String> roles) {

        if (users.existsByLogin(login)) return "Login already used";
        if (users.existsByEmail(email)) return "Email already used";

        User u = new User();
        u.setLogin(login);
        u.setEmail(email);
        u.setPassword(encoder.encode(password));

        if (roles == null || roles.isEmpty()) {
            u.setRoles(Set.of(Role.GUEST));
        } else {
            Set<Role> roleSet = new HashSet<>();
            for (String r : roles) {
                try {
                    roleSet.add(Role.valueOf(r.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    return "Invalid role: " + r;
                }
            }
            u.setRoles(roleSet);
        }

        users.save(u);
        return generateToken(login);
    }

    @PostMapping("/login")
    public String login(@RequestParam String login,
                        @RequestParam String password) {

        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "Invalid login";

        User user = opt.get();
        if (!encoder.matches(password, user.getPassword())) return "Wrong password";

        return generateToken(login);
    }

    @GetMapping("/check")
    public String check(@RequestHeader("Authorization") String header) {
        String token = parseToken(header);
        Token t = tokens.get(token);
        if (t == null) return "Token not found";
        if (t.getExpires().isBefore(LocalDateTime.now())) return "Token expired";
        return "Token valid for: " + t.getUsername();
    }

    @PostMapping("/revoke")
    public String revoke(@RequestHeader("Authorization") String header) {
        String token = parseToken(header);
        tokens.remove(token);
        return "Token revoked";
    }

    @PostMapping("/refresh")
    public String refresh(@RequestHeader("Authorization") String header) {
        String oldToken = parseToken(header);
        Token t = tokens.get(oldToken);
        if (t == null) return "Token not found";
        if (t.getExpires().isBefore(LocalDateTime.now())) return "Token expired";

        String newToken = UUID.randomUUID().toString();
        tokens.put(newToken, new Token(newToken, t.getUsername(), LocalDateTime.now().plusMinutes(tokenMinutes)));
        tokens.remove(oldToken);

        return newToken;
    }

    @GetMapping("/user-info")
    public Object getUserInfo(@RequestParam String login) {
        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "User not found";

        User u = opt.get();

        Map<String, Object> info = new HashMap<>();
        info.put("id", u.getId());
        info.put("login", u.getLogin());
        info.put("password", u.getPassword());
        info.put("email", u.getEmail());
        info.put("roles", u.getRoles());

        return info;
    }

    private String generateToken(String username) {
        String token = UUID.randomUUID().toString();
        tokens.put(token, new Token(token, username, LocalDateTime.now().plusMinutes(tokenMinutes)));
        return token;
    }

    private String parseToken(String header) {
        if (header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return header;
    }
}
