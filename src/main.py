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
