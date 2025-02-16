CREATE TABLE image (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_filename TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER NOT NULL,
    is_encrypted BOOLEAN,
    encryption_type TEXT,
    salt TEXT
);

