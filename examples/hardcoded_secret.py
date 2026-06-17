# This file is intentionally vulnerable for testing the scanner.

API_KEY = "demo-placeholder-api-key-12345"
DATABASE_PASSWORD = "password123"


def connect_to_service():
    return {
        "api_key": API_KEY,
        "password": DATABASE_PASSWORD,
    }
