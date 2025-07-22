package com.example.auth.controller;

import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    private final SecretKey secretKey;

    public AuthController(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
        this.secretKey = Keys.hmacShaKeyFor("ОченьДлинныйИСложныйСекретныйКлючДляJWT1234567890".getBytes());
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
        return generateToken(login, u.getRoles());
    }

    @PostMapping("/login")
    public String login(@RequestParam String login,
                        @RequestParam String password) {

        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "Invalid login";

        User user = opt.get();
        if (!encoder.matches(password, user.getPassword())) return "Wrong password";

        return generateToken(login, user.getRoles());
    }

    @GetMapping("/check")
    public String check() {
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return "Unauthorized";
        }
        return "Token valid for: " + auth.getName();
    }

    @GetMapping("/user-info")
    public Object getUserInfo(@RequestParam String login) {
        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "User not found";

        User u = opt.get();

        var info = new java.util.HashMap<String, Object>();
        info.put("id", u.getId());
        info.put("login", u.getLogin());
        info.put("email", u.getEmail());
        info.put("roles", u.getRoles());

        return info;
    }

    private String generateToken(String username, Set<Role> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(900))) // 15 минут
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}
