# This file is intentionally vulnerable for testing the scanner.


def read_uploaded_file(filename):
    path = "/tmp/uploads/" + filename
    with open(path, "r", encoding="utf-8") as file:
        return file.read()
