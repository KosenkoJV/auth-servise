package com.example.auth.model;

import jakarta.persistence.*;
import java.util.Set;

// Класс описывающий таблицу users в базе данных
@Entity
@Table(name = "users")
public class User {

    // Первичный ключ
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Поле login должно быть уникальным
    @Column(unique = true)
    private String login;

    // Поле email тоже уникально
    @Column(unique = true)
    private String email;

    // Поле для хранения хэшированного пароля
    private String password;

    // @Enumerated(EnumType.STRING) — роли хранятся в базе в виде строк (например, "ADMIN", "USER")
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;

    // Геттеры и сеттеры для всех полей

    public Long getId() {
        return id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
