# This file is intentionally vulnerable for testing the scanner.

import sqlite3


def find_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return cursor.execute(query).fetchall()
