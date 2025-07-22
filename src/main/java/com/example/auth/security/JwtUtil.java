package com.example.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    // Генерируем секретный ключ
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Время жизни JWT токена в миллисекундах (15 минут)
    private final long jwtExpirationMs = 15 * 60 * 1000;

    // Метод генерации JWT токена с логином и ролями пользователя
    public String generateToken(String username, Set<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(username)            // Устанавливаем subject (логин пользователя)
                .claim("roles", roles)           // Добавляем claim с ролями
                .setIssuedAt(now)                // Время создания токена
                .setExpiration(expiryDate)       // Время истечения токена
                .signWith(key)                  // Подписываем токен секретным ключом
                .compact();                     // Формируем готовую строку JWT
    }

    // Метод валидации токена — проверяет подпись и структуру
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;                    // Если парсинг успешен — токен валиден
        } catch (JwtException | IllegalArgumentException e) {
            return false;                   // В случае ошибки — токен невалиден
        }
    }

    // Получение имени пользователя (subject) из токена
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Получение ролей пользователя из токена
    public Set<String> getRolesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Object rolesObject = claims.get("roles");
        if (rolesObject instanceof List<?>) {
            // Преобразуем список ролей в Set<String>
            return ((List<?>) rolesObject).stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }
        return Set.of(); // Если ролей нет или они в неправильном формате — возвращаем пустой набор
    }
}
