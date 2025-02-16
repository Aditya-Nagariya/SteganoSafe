# Database Migration Instructions

1. Verify your User model in `models.py` has:
   ```python
   is_verified = db.Column(db.Boolean, default=False)
   ```
2. Ensure your migration file (`migrations/versions/<timestamp>_add_is_verified_to_user.py`) has the correct previous revision id.
3. From the project root, run:
   ```bash
   flask db upgrade
   ```
4. If the column is still missing, run the following SQL on your SQLite database (or use the provided script):
   ```sql
   ALTER TABLE user ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT 0;
   ```
5. Restart your application.

These steps will update your SQLite database to include the `is_verified` column, resolving the "no such column" error.
