import bcrypt

password = "my_secure_password"
hashed = bcrypt.hashpw(password.encode(),bcrypt.gensalt())

# print("Пароль", password)
# print("Хэш", hashed)

# Проверка пароля
def check_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password)

# test

print("Правильный пароль ", check_password("my_secure_password", hashed)) # true
print("Неправильный пароль ", check_password("valera220202002", hashed)) # false