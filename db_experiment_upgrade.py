import sqlite3
import logging

logger = logging.getLogger(__name__)


DB_PATH = 'arvo_loc_runs.db'
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    cursor = conn.cursor()
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS experiments (
            experiment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_tag TEXT UNIQUE NOT NULL,
            description TEXT,
            prompt_template TEXT,
            markdown_json TEXT
        )''')

        cursor.execute('''ALTER TABLE runs ADD COLUMN experiment_id INTEGER REFERENCES experiments(experiment_id);
        ''')

        cursor.execute('''ALTER TABLE patch_data DROP COLUMN experiment_tag
        ''')
        conn.commit()

    except sqlite3.Error as e:
        logger.error(f"An error occurred: {e}")

    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    logging.basicConfig(
        filename='db_experiment_upgrade.log', 
        level=logging.DEBUG,             
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Script started directly.")
    init_db()