# Data Extraction & Secure Validation Assignment

A Python script that extracts structured data (emails, credit cards, phone
numbers, URLs, hashtags) from raw text using regex, while rejecting tickets
that contain hostile/malicious content before extracting anything from them.

## What it does

1. Reads `input/raw-text.txt` (falls back to a built-in sample dataset if
   the file isn't found).
2. Splits the text into separate tickets using `---` as the divider.
3. Scans each ticket for red flags (`<script>` tags, SQL injection patterns,
   inline JS event handlers). Flagged tickets are marked
   `rejected_unsafe_input` and skipped entirely — nothing is extracted from them.
4. For safe tickets, extracts:
   - **Emails** — classified as `ALU Official`, `ALU Alumni`, `ALU SI`, or
     `External / Personal` based on domain.
   - **Credit cards** — matched by shape, verified with the Luhn checksum,
     and masked (`**** **** **** 0366`) so full numbers never appear in output.
   - **Phone numbers** — supports `+250 788 123 456`, `(078) 456-7890`, and
     `0788-990-112` style formats.
   - **URLs**.
   - **Hashtags** (must start with a letter, so ticket numbers like `#1`
     aren't caught).
5. Prints a readable summary to the console.
6. Saves full structured results to `output/sample-output.json`.

## Project structure

```
alu-regex-data-extraction_{GithubUsername}/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
```

## How to run it

```bash
python3 src/main.py
```

Run it from the project root so it can find `input/raw-text.txt`. If that
file is missing, the script uses its built-in sample dataset instead.

## Notes

- Card numbers in the sample input are well-known Luhn-valid **test**
  numbers — not real cards.
- Ticket #3 is intentionally malicious, to demonstrate the rejection logic.
- `david.niyonzima@student.alueducation.com` is a deliberate edge case: it
  looks ALU-related but doesn't match any of the three official ALU domain
  patterns, so it's correctly classified as `External / Personal`.
