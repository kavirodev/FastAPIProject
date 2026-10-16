import sqlite3
import bcrypt
import secrets
import requests

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
STATIC_DIR = BASE_DIR / "static"


# ---------- DATABASE ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Миграция старой базы: добавляем completed, если столбца ещё нет.
        task_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "completed" not in task_columns:
            conn.execute(
                "ALTER TABLE tasks ADD COLUMN completed INTEGER NOT NULL DEFAULT 0"
            )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS favorite_movies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE
            )
        """)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Task & Movie API",
    description="CRUD, SQLite, bcrypt authentication and HTML frontend",
    version="1.0.0",
    lifespan=lifespan
)

STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------- MODELS ----------

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=6, max_length=128)


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class TaskUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    completed: bool


class MovieCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class MovieUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)


# ---------- AUTHENTICATION ----------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed.encode("utf-8")
    )


def get_current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization: Bearer <token> required"
        )

    token = authorization.removeprefix("Bearer ").strip()

    with get_db() as conn:
        user = conn.execute(
            "SELECT id, username FROM users WHERE token = ?",
            (token,)
        ).fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid token. Please log in again."
        )

    return user


# ---------- HOME ----------

@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api")
def api_home():
    return {
        "message": "API is running!",
        "docs": "/docs",
        "frontend": "/",
        "register": "/register",
        "login": "/login",
        "tasks": "/api/tasks",
        "favorite_movies": "/api/favorite-movies"
    }


# ---------- REGISTER ----------

@app.post("/register", status_code=201)
def register(data: Credentials):
    username = data.username.strip()

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty"
        )

    with get_db() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, hash_password(data.password))
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Username already exists"
            )

    return {
        "message": "User created",
        "user": {
            "id": cursor.lastrowid,
            "username": username
        }
    }


# ---------- LOGIN ----------

@app.post("/login")
def login(data: Credentials):
    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (data.username.strip(),)
        ).fetchone()

        if not user or not check_password(
            data.password,
            user["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )

        token = secrets.token_urlsafe(32)

        conn.execute(
            "UPDATE users SET token = ? WHERE id = ?",
            (token, user["id"])
        )

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer"
    }


# ---------- LOGOUT ----------

@app.post("/logout")
def logout(authorization: str = Header(default="")):
    user = get_current_user(authorization)

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET token = NULL WHERE id = ?",
            (user["id"],)
        )

    return {"message": "Logged out successfully"}


# ==========================================
# TASKS CRUD
# ==========================================

# CREATE
@app.post("/api/tasks", status_code=201)
def create_task(
    data: TaskCreate,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)
    title = data.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Title required")

    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO tasks (user_id, title)
            VALUES (?, ?)
            """,
            (user["id"], title)
        )

        row = conn.execute(
            """
            SELECT id, title, completed
            FROM tasks WHERE id = ?
            """,
            (cursor.lastrowid,)
        ).fetchone()

    return dict(row)


# READ ALL
@app.get("/api/tasks")
def list_tasks(authorization: str = Header(default="")):
    user = get_current_user(authorization)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, title, completed
            FROM tasks
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user["id"],)
        ).fetchall()

    return {"tasks": [dict(row) for row in rows]}


# READ ONE
@app.get("/api/tasks/{task_id}")
def get_task(
    task_id: int,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)

    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, title, completed
            FROM tasks
            WHERE id = ? AND user_id = ?
            """,
            (task_id, user["id"])
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Task not found")

    return dict(row)


# UPDATE
@app.put("/api/tasks/{task_id}")
def update_task(
    task_id: int,
    data: TaskUpdate,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)
    title = data.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Title required")

    with get_db() as conn:
        cursor = conn.execute(
            """
            UPDATE tasks
            SET title = ?, completed = ?
            WHERE id = ? AND user_id = ?
            """,
            (title, int(data.completed), task_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Task not found")

        row = conn.execute(
            """
            SELECT id, title, completed
            FROM tasks WHERE id = ?
            """,
            (task_id,)
        ).fetchone()

    return dict(row)


# DELETE
@app.delete("/api/tasks/{task_id}")
def delete_task(
    task_id: int,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)

    with get_db() as conn:
        cursor = conn.execute(
            """
            DELETE FROM tasks
            WHERE id = ? AND user_id = ?
            """,
            (task_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Task not found")

    return {"message": "Task deleted", "id": task_id}


# ==========================================
# FAVORITE MOVIES CRUD
# ==========================================

# CREATE
@app.post("/api/favorite-movies", status_code=201)
def create_movie(
    data: MovieCreate,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)
    title = data.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Title required")

    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO favorite_movies (user_id, title)
            VALUES (?, ?)
            """,
            (user["id"], title)
        )

        row = conn.execute(
            """
            SELECT id, title FROM favorite_movies
            WHERE id = ?
            """,
            (cursor.lastrowid,)
        ).fetchone()

    return dict(row)


# READ ALL
@app.get("/api/favorite-movies")
def list_movies(authorization: str = Header(default="")):
    user = get_current_user(authorization)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, title
            FROM favorite_movies
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user["id"],)
        ).fetchall()

    return {"favorite_movies": [dict(row) for row in rows]}


# READ ONE
@app.get("/api/favorite-movies/{movie_id}")
def get_movie(
    movie_id: int,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)

    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, title
            FROM favorite_movies
            WHERE id = ? AND user_id = ?
            """,
            (movie_id, user["id"])
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Movie not found")

    return dict(row)


# UPDATE
@app.put("/api/favorite-movies/{movie_id}")
def update_movie(
    movie_id: int,
    data: MovieUpdate,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)
    title = data.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Title required")

    with get_db() as conn:
        cursor = conn.execute(
            """
            UPDATE favorite_movies
            SET title = ?
            WHERE id = ? AND user_id = ?
            """,
            (title, movie_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Movie not found")

        row = conn.execute(
            "SELECT id, title FROM favorite_movies WHERE id = ?",
            (movie_id,)
        ).fetchone()

    return dict(row)


# DELETE
@app.delete("/api/favorite-movies/{movie_id}")
def delete_movie(
    movie_id: int,
    authorization: str = Header(default="")
):
    user = get_current_user(authorization)

    with get_db() as conn:
        cursor = conn.execute(
            """
            DELETE FROM favorite_movies
            WHERE id = ? AND user_id = ?
            """,
            (movie_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Movie not found")

    return {"message": "Movie deleted", "id": movie_id}


# ---------- EXTERNAL CAT FACT API ----------

@app.get("/api/catfact")
def get_catfact():
    try:
        response = requests.get(
            "https://catfact.ninja/fact",
            timeout=10
        )
        response.raise_for_status()

        return {"data": response.json()}

    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="Could not connect to Cat Fact API"
        )
