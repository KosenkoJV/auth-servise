package com.example.auth.config;

// Импортируем фильтр аутентификации, который проверяет JWT в каждом запросе
import com.example.auth.filter.JwtAuthenticationFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // Указывает, что этот класс содержит настройки Spring (настройки безопасности)
public class SecurityConfig {

    // Секретный ключ
    private final String jwtSecret = "ОченьДлинныйИСложныйСекретныйКлючДляJWT1234567890";

    @Bean // Метод настраивает SecurityFilterChain
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Отключаем защиту от CSRF-атак
                .csrf(csrf -> csrf.disable())

                // Указываем какие запросы разрешены без аутентификации
                .authorizeHttpRequests(auth -> auth
                        // Разрешаем всем доступ к конечным точкам регистрации и логина
                        .requestMatchers("/auth/register", "/auth/login").permitAll()
                        // Все остальные запросы требуют аутентификации
                        .anyRequest().authenticated()
                )

                // Добавляем фильтр JwtAuthenticationFilter перед стандартным UsernamePasswordAuthenticationFilter
                // Это позволяет обрабатывать JWT до стандартной логики аутентификации Spring Security
                .addFilterBefore(new JwtAuthenticationFilter(jwtSecret), UsernamePasswordAuthenticationFilter.class)

                // Включаем базовую HTTP-аутентификацию
                .httpBasic(Customizer.withDefaults());

        // Возвращаем настроенную цепочку фильтров
        return http.build();
    }
}
