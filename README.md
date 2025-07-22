функционал:

- Регистрировать новых пользователей с уникальным логином и email
- Авторизовывать существующих пользователей
- Назначать роли: `ADMIN`, `PREMIUM_USER`, `GUEST`
- Использовать JWT-токены с ограниченным временем жизни (15 минут)
- Проверять валидность токена
- Получать информацию о пользователе по логину


	1 Точка входа "AuthApplication" 
// После запуска дальнейшие действия будут проводится в терминале


	2 Регистрация пользователя

 $response = Invoke-WebRequest -Uri "http://localhost:8080/auth/register" -Method POST -Body @{
    login = "danil"
    email = "danil@mail.com"
    password = "1234"
    roles = "ADMIN"
}
// login, emal, password, roles можно менять 


	3 Получение токена
$token = $response.Content
Write-Output "Token: $token"
//Будет присвоен токен


	4 Проверка токена
Invoke-WebRequest -Uri "http://localhost:8080/auth/check" -Method GET -Headers @{ Authorization = "Bearer $token" }


	5 Получение информации о пользователе
Invoke-WebRequest -Uri "http://localhost:8080/auth/user-info?login=danil" -Method GET -Headers @{ Authorization = "Bearer $token" }
//login=danil можете вставить тот логин который указывали при регистрации


