import os


DATABASE_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "linux_patching"),
    "user": os.getenv("DB_USER", "patchuser"),
    "password": os.getenv("DB_PASSWORD"),
}
