# Data Extraction & Secure Validation Assignment

A small Python program that reads messy, real-world-style text.

1. Detect and reject tickets that contain hostile/malicious content
   (e.g. script injection, SQL injection attempts).
2. Extract useful data from every ticket that is safe:
   - **Email addresses** — and classify ALU emails as `Official`,
     `Alumni`, or `SI`.
   - **Credit card numbers** — validated with the Luhn checksum
     algorithm and **masked** so only the last 4 digits ever appear
     in the output (real systems should never print full card numbers).
   - **Phone numbers** (multiple formats: `+250 788 123 456`,
     `(078) 456-7890`, `0788-990-112`).
   - **URLs**.
   - **Hashtags**

## Why the security step matters

Text coming from a real API or a real user can never be trusted blindly.
Someone could try to slip in a `<script>` tag or a fake SQL command hoping
the system just "runs" it as-is. Before this program extracts anything
from a ticket, it first scans that ticket for red-flag patterns (script
tags, `DROP TABLE`, SQL comment markers, inline JS event handlers like
`onerror=`). If any of those are found, **the whole ticket is rejected**
and nothing is extracted from it — we don't try to "clean" it and use it
anyway, because at that point we can no longer trust its structure.


## How it works, step by step

1. `read_input_file()` opens `input/raw-text.txt` and reads it as one
   big string.
2. `split_into_tickets()` splits that string into separate tickets,
   using the `---` divider line as the separator. This mimics
   processing one record at a time, like a real system would.
3. For each ticket, `is_suspicious()` checks it against a list of
   red-flag regex patterns. If anything matches, the ticket is marked
   `"rejected_unsafe_input"` and skipped.
4. If the ticket is safe, `extract_from_ticket()` runs five different
   regex patterns over the text to pull out emails, credit cards,
   phone numbers, URLs, and hashtags.
   - Every matched credit-card-looking number is passed through the
     **Luhn algorithm** (the same checksum real card issuers use) to
     filter out random 13-19 digit numbers that aren't really cards.
   - Every email is compared against ALU's three domain patterns
     (`@alueducation.com`, `@alumni.alueducation.com`,
     `@si.alueducation.com`) and labeled accordingly.
5. `print_summary()` prints a human-readable report to the console.
6. `save_json()` writes the full structured results to
   `output/sample-output.json`.

## How to run it

1. Make sure you have Python 3 installed (`python3 --version`).
2. From the root of this project folder, run:

   ```bash
   cd src
   python3 main.py
   ```


3. You'll see a summary printed in the terminal, and a fresh
   `output/sample-output.json` file will be created/updated.

## Notes on the sample input

- `input/raw-text.txt` contains 5 fake tickets separated by `---` lines.
- Ticket #3 is intentionally malicious (contains a `<script>` tag and a
  SQL injection attempt) to demonstrate that the program correctly
  rejects it instead of extracting data from it.
- The credit card numbers used are well-known **test numbers** that pass
  the Luhn checksum — they are not real cards.
- One email (`david.niyonzima@alueducation.com`) is a deliberate
  edge case: it looks ALU-related but does **not** match any of the three
  official ALU domain patterns exactly, so it is correctly classified as
  "External / Personal". This shows the regex patterns are precise
  rather than just guessing based on keywords.
