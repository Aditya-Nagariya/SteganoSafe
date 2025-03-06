"""
Database schema upgrade utility for SteganoSafe
"""
import os
import sys
import sqlite3
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('db_upgrade.log')
    ]
)
logger = logging.getLogger(__name__)

def get_db_path():
    """Get the SQLite database path"""
    # Assume the database is in a data folder in the project root
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(app_dir, 'data')
    db_path = os.path.join(data_dir, 'app.db')
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found at: {db_path}")
        return None
    
    return db_path

def check_table_columns(conn, table_name):
    """Check columns for a specific table"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name});")
    return [col[1] for col in cursor.fetchall()]

def add_column_if_missing(conn, table_name, column_name, column_type):
    """Add a column if it's missing from the table"""
    cursor = conn.cursor()
    columns = check_table_columns(conn, table_name)
    
    if column_name not in columns:
        logger.info(f"Adding {column_name} column to {table_name} table")
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type};")
        conn.commit()
        return True
    
    return False

def rename_column(conn, table_name, old_column, new_column, column_type):
    """Rename a column in a table"""
    # SQLite doesn't support direct column renaming, so we:
    # 1. Create a new table with the desired schema
    # 2. Copy data from the old table
    # 3. Drop the old table
    # 4. Rename the new table to the original name
    
    cursor = conn.cursor()
    
    # Get all columns except the one we're renaming
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()
    
    # Create list of columns for new table
    new_columns = []
    old_columns = []
    
    for col in columns:
        col_name = col[1]
        col_type = col[2]
        not_null = "NOT NULL" if col[3] == 1 else ""
        default = f"DEFAULT {col[4]}" if col[4] is not None else ""
        
        if col_name == old_column:
            # Rename this column
            new_columns.append(f"{new_column} {column_type} {not_null} {default}")
            old_columns.append(col_name)
        else:
            # Keep this column the same
            new_columns.append(f"{col_name} {col_type} {not_null} {default}")
            old_columns.append(col_name)
    
    # Create new table
    temp_table = f"{table_name}_temp"
    create_sql = f"CREATE TABLE {temp_table} ({', '.join(new_columns)})"
    cursor.execute(create_sql)
    
    # Copy data
    copy_columns = ", ".join(old_columns)
    cursor.execute(f"INSERT INTO {temp_table} SELECT {copy_columns} FROM {table_name}")
    
    # Drop old table
    cursor.execute(f"DROP TABLE {table_name}")
    
    # Rename new table
    cursor.execute(f"ALTER TABLE {temp_table} RENAME TO {table_name}")
    
    conn.commit()
    logger.info(f"Successfully renamed column {old_column} to {new_column} in {table_name}")

def fix_stego_images_table(conn):
    """Fix the stego_images table"""
    columns = check_table_columns(conn, 'stego_images')
    
    # Check for timestamp/created_at issues
    if 'timestamp' in columns and 'created_at' not in columns:
        # Rename timestamp to created_at
        rename_column(conn, 'stego_images', 'timestamp', 'created_at', 'DATETIME')
    elif 'timestamp' not in columns and 'created_at' not in columns:
        # Add created_at column
        add_column_if_missing(conn, 'stego_images', 'created_at', 'DATETIME')
        
        # Set default value for existing rows
        logger.info(f"Setting default created_at value for existing rows")
        cursor = conn.cursor()
        cursor.execute("UPDATE stego_images SET created_at = CURRENT_TIMESTAMP")
        conn.commit()

def fix_activity_logs_table(conn):
    """Fix the activity_logs table"""
    if 'activity_logs' not in get_tables(conn):
        logger.info("activity_logs table doesn't exist, skipping")
        return
        
    columns = check_table_columns(conn, 'activity_logs')
    
    # Check for timestamp column
    if 'timestamp' not in columns:
        add_column_if_missing(conn, 'activity_logs', 'timestamp', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
    
    # Check for ip_address column
    if 'ip_address' not in columns:
        add_column_if_missing(conn, 'activity_logs', 'ip_address', 'VARCHAR(50)')

def get_tables(conn):
    """Get all tables in the database"""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return [table[0] for table in cursor.fetchall()]

def main():
    """Main function to run the database upgrade"""
    logger.info("Starting database upgrade...")
    
    db_path = get_db_path()
    if not db_path:
        logger.error("Database path not found, aborting")
        return False
    
    logger.info(f"Using database at {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        
        # Get all tables
        tables = get_tables(conn)
        logger.info(f"Found tables: {tables}")
        
        # Fix stego_images table
        if 'stego_images' in tables:
            logger.info("Checking stego_images table")
            fix_stego_images_table(conn)
        else:
            logger.warning("stego_images table not found!")
            
        # Fix activity_logs table
        if 'activity_logs' in tables:
            logger.info("Checking activity_logs table")
            fix_activity_logs_table(conn)
        
        conn.close()
        logger.info("Database upgrade completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error during database upgrade: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
