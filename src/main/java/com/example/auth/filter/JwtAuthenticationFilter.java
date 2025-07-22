package com.example.auth.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Секретный ключ для проверки подписи JWT
    private final SecretKey secretKey;

    // Конструктор, принимает строковый секрет и конвертирует его в SecretKey
    public JwtAuthenticationFilter(String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // Метод, который вызывается для каждого входящего HTTP-запроса
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Получаем заголовок Authorization
        String header = request.getHeader("Authorization");

        // Если заголовок отсутствует или не начинается с "Bearer ", пропускаем фильтр дальше без аутентификации
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Извлекаем сам JWT-токен, убирая префикс "Bearer "
        String token = header.substring(7);

        try {
            // Парсим JWT, проверяем подпись с помощью секретного ключа и получаем тело токена (claims)
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Извлекаем из claims имя пользователя (subject)
            String username = claims.getSubject();

            // Извлекаем список ролей из claims (ожидается список строк)
            List<String> roles = claims.get("roles", List.class);

            if (username != null) {
                // Создаем объект аутентификации с именем пользователя и ролями
                // Роли преобразуем в объекты SimpleGrantedAuthority с префиксом "ROLE_"
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        roles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList())
                );

                // Устанавливаем аутентификацию в SecurityContext — дальше Spring Security будет считать пользователя аутентифицированным
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception e) {
            // Если возникла ошибка при разборе токена (например, он просрочен, изменен или неверный),
            // очищаем контекст безопасности (пользователь не аутентифицирован)
            SecurityContextHolder.clearContext();
        }

        // Продолжаем цепочку фильтров
        filterChain.doFilter(request, response);
    }
}
