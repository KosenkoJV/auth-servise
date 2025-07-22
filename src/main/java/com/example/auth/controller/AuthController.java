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
@RequestMapping("/auth") // Базовый путь для всех эндпоинтов этого контроллера — /auth
public class AuthController {

    // Репозиторий для работы с пользователями в БД
    private final UserRepository users;

    // Кодировщик паролей, для безопасного хранения пароля
    private final PasswordEncoder encoder;

    // Секретный ключ для создания и проверки JWT токенов
    private final SecretKey secretKey;

    // Конструктор с внедрением зависимостей (UserRepository и PasswordEncoder)
    // Также инициализируем секретный ключ из заранее заданной строки
    public AuthController(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
        this.secretKey = Keys.hmacShaKeyFor("ОченьДлинныйИСложныйСекретныйКлючДляJWT1234567890".getBytes());
    }

    // Эндпоинт для регистрации нового пользователя
    // Принимает логин, email, пароль и необязательный набор ролей
    @PostMapping("/register")
    public String register(@RequestParam String login,
                           @RequestParam String email,
                           @RequestParam String password,
                           @RequestParam(required = false) Set<String> roles) {

        // Проверяем, что логин уникален
        if (users.existsByLogin(login)) return "Login already used";

        // Проверяем, что email уникален
        if (users.existsByEmail(email)) return "Email already used";

        // Создаем нового пользователя и задаем поля
        User u = new User();
        u.setLogin(login);
        u.setEmail(email);

        // Хэшируем пароль перед сохранением
        u.setPassword(encoder.encode(password));

        // Если роли не переданы, назначаем роль GUEST по умолчанию
        if (roles == null || roles.isEmpty()) {
            u.setRoles(Set.of(Role.GUEST));
        } else {
            // Иначе пытаемся преобразовать строки ролей в enum Role
            Set<Role> roleSet = new HashSet<>();
            for (String r : roles) {
                try {
                    roleSet.add(Role.valueOf(r.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    // Если роль невалидная, возвращаем ошибку
                    return "Invalid role: " + r;
                }
            }
            u.setRoles(roleSet);
        }

        // Сохраняем пользователя в базу
        users.save(u);

        // Возвращаем сгенерированный JWT токен для нового пользователя
        return generateToken(login, u.getRoles());
    }

    // Эндпоинт для входа пользователя (логин + пароль)
    @PostMapping("/login")
    public String login(@RequestParam String login,
                        @RequestParam String password) {

        // Ищем пользователя по логину
        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "Invalid login";

        User user = opt.get();

        // Проверяем, совпадает ли пароль с хешем в базе
        if (!encoder.matches(password, user.getPassword())) return "Wrong password";

        // Если пароль верный — генерируем и возвращаем JWT токен
        return generateToken(login, user.getRoles());
    }

    // Эндпоинт проверки валидности токена (доступен только при аутентификации)
    @GetMapping("/check")
    public String check() {
        // Получаем информацию о текущей аутентификации
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();

        // Проверяем, что пользователь аутентифицирован и не анонимный
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return "Unauthorized";
        }

        // Возвращаем имя пользователя, для которого валиден токен
        return "Token valid for: " + auth.getName();
    }

    // Эндпоинт для получения информации о пользователе по логину
    @GetMapping("/user-info")
    public Object getUserInfo(@RequestParam String login) {
        // Ищем пользователя в базе
        Optional<User> opt = users.findByLogin(login);
        if (opt.isEmpty()) return "User not found";

        User u = opt.get();

        // Формируем карту с данными пользователя, которую вернем клиенту
        var info = new java.util.HashMap<String, Object>();
        info.put("id", u.getId());
        info.put("login", u.getLogin());
        info.put("email", u.getEmail());
        info.put("roles", u.getRoles());

        return info;
    }

    // Вспомогательный метод для генерации JWT токена
    private String generateToken(String username, Set<Role> roles) {
        Instant now = Instant.now();

        // Строим JWT токен с указанием:
        // - subject (логин пользователя)
        // - claim roles (список ролей в виде строк)
        // - время создания
        // - время истечения (через 15 минут)
        // - подпись с помощью секретного ключа
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(900))) // токен живет 15 минут
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}
