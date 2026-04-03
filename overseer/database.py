import sys
import mysql.connector
from mysql.connector import Error
from mysql.connector.pooling import MySQLConnectionPool

from overseer.config import Config

_INSERT_SQL = """
    INSERT INTO nginx_requests
        (recorded_at, ip, host, uri, referrer, method, status,
         upstream, duration, user_agent, country,
         threat_score, is_bot, is_attack, bot_reason)
    VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def create_pool(config: Config) -> MySQLConnectionPool:
    return MySQLConnectionPool(**config.to_pool_config())


def insert_rows(pool: MySQLConnectionPool, rows: list[tuple]) -> None:
    if not rows:
        return
    conn = None
    try:
        conn = pool.get_connection()
        cursor = conn.cursor()
        cursor.executemany(_INSERT_SQL, rows)
        conn.commit()
        cursor.close()
    except Error as exc:
        sys.stderr.write(f"Overseer DB error: {exc}\n")
    finally:
        if conn and conn.is_connected():
            conn.close()