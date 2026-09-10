import re
import json
import os


def read_input_file(filepath):
    """Open the raw text file and return its full contents as one big string."""
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()
def split_into_tickets(raw_text):
    """
    Our input file uses a line of dashes ('---') to separate one ticket
    from the next. We split on that so we can look at each ticket one
    at a time, which mimics how a real system would process one record
    (one API response, one form submission, etc.) at a time.
    """
    tickets = re.split(r"\n-{3,}\n", raw_text)
return [t.strip() for t in tickets if t.strip()]

SUSPICIOUS_PATTERNS = [
    r"<script.*?>",
    r"on\w+\s*=\s*['\"]?",
    r"drop\s+table",
    r"--\s*$",
    r"';.*--",
    r"<img[^>]*onerror",
]

SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)


def is_suspicious(text):
    """Return True if the text contains any red-flag pattern."""
    return bool(SUSPICIOUS_REGEX.search(text))

EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

ALU_OFFICIAL_DOMAIN = re.compile(r"@alueducation\.com$", re.IGNORECASE)
ALU_ALUMNI_DOMAIN = re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_DOMAIN = re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)


def classify_email(email):
    """Decide which category an email belongs to."""
    if ALU_ALUMNI_DOMAIN.search(email):
        return "ALU Alumni"
    if ALU_SI_DOMAIN.search(email):
        return "ALU SI (School of ...)"
    if ALU_OFFICIAL_DOMAIN.search(email):
        return "ALU Official"
    return "External / Personal"
