package com.example.auth.repository;

import com.example.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// Репозиторий для работы с User в базе данных
public interface UserRepository extends JpaRepository<User, Long> {

    // Метод проверяет, существует ли пользователь с указанным логином
    boolean existsByLogin(String login);

    // Метод проверяет, существует ли пользователь с указанным email
    boolean existsByEmail(String email);

    // Метод ищет пользователя по логину, возвращая Optional для обработки отсутствия пользователя
    Optional<User> findByLogin(String login);
}
