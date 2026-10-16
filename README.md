# FastAPI Project

REST API на FastAPI с SQLite, регистрацией и авторизацией через bcrypt, CRUD-операциями для задач и любимых фильмов, а также HTML-интерфейсом.

# Возможности

- Регистрация и вход в аккаунт
- Хранение паролей в виде bcrypt-хэшей
- CRUD для задач и любимых фильмов
- SQLite для хранения данных
- HTML-фронтенд
- Swagger-документация

# Запуск

1. Установить зависимости:
   pip install fastapi
   pip install uvicorn
   pip install bcrypt
   pip install request


2. Запустить сервер:
   uvicorn main:app --reload

3. Открыть в браузере:
   - Интерфейс: http://127.0.0.1:8000/
   - Swagger: http://127.0.0.1:8000/docs
