import re
import json
import os

DEFAULT_RAW_TEXT = """---
Customer support ticket #1
Name: David Niyonzima
Email: david.niyonzima@student.alueducation.com
Alternate: d.niyonzima@alumni.alueducation.com
Support: si-support@si.alueducation.com
Phone: +250 788 123 456
Mobile: (078) 456-7890
Card: 4532 1188 2003 0366
Card2: 4556 6501 1234 2832
URL: https://example.edu/portal
Hash: #StudentLife
---
Customer support ticket #2
Name: Grace Uwimana
Email: grace.uwimana@gmail.com
Phone: 0788-990-112
Card: 4556 2822 1987 0004
URL: https://marketreview.rw/blog/farmers-app-2026
URL2: http://www.oldsite-example.com/reviews?id=88&ref=home
Hash: #FarmTechRwanda
Hash2: #SupportLocalFarmers
---
Customer support ticket #3
Name: Malicious test
Comment: <script>alert('x')</script>
DROP TABLE users;
---
Customer support ticket #4
Name: Eric Mugisha
Email: eric.mugisha@alueducation.com
Phone: 0788-990-112
URL: https://support.aluerp.com/tickets/new
---
Customer support ticket #5
Name: Staff Desk
Email: staff@alueducation.com
Hash: #Q3Report
"""

# STEP 1: Read the raw input file

def read_input_file(filepath):
    if not os.path.exists(filepath):
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input", "raw-text.txt")
        if os.path.exists(default_path):
            filepath = default_path
        else:
            return DEFAULT_RAW_TEXT

    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()

# STEP 2: Spliting the big text into separate "tickets"

def split_into_tickets(raw_text):

    # The regex below matches a line made up of 3 or more dashes.
    tickets = re.split(r"\n-{3,}\n", raw_text)
    # Remove empty/whitespace-only chunks
    return [t.strip() for t in tickets if t.strip()]


# STEP 3: Security check - decide if a ticket is safe to process

SUSPICIOUS_PATTERNS = [
    r"<script.*?>",               
    r"on\w+\s*=\s*['\"]?",       
    r"drop\s+table",              
    r"--\s*$",                    
    r"';.*--",                   
    r"<img[^>]*onerror",         
]

# Combine all the individual patterns into ONE compiled pattern for speed.
# re.IGNORECASE means "HACK", "hack", and "HaCk" are all treated the same.
SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)


def is_suspicious(text):
    """Return True if the text contains any red-flag pattern."""
    return bool(SUSPICIOUS_REGEX.search(text))

# STEP 4: The actual regex patterns for each data type we must extract


EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

# ALU-specific domains we need to classify separately.
ALU_OFFICIAL_DOMAIN = re.compile(r"@alueducation\.com$", re.IGNORECASE)
ALU_ALUMNI_DOMAIN = re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_DOMAIN = re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)


def classify_email(email):
    if ALU_ALUMNI_DOMAIN.search(email):
        return "ALU Alumni"
    if ALU_SI_DOMAIN.search(email):
        return "ALU SI (School of ...)"
    if ALU_OFFICIAL_DOMAIN.search(email):
        return "ALU Official"
    return "External / Personal"


# Credit Card Numbers
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_checksum(card_number):

    digits = [int(d) for d in card_number]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_card(card_number):

    digits_only = re.sub(r"[ -]", "", card_number)
    return "**** **** **** " + digits_only[-4:]


# Phone Numbers 

PHONE_REGEX = re.compile(
    r"(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{2,4}(?:[ -]\d{3,4}){1,3}"
)

# URLs
URL_REGEX = re.compile(r"https?://[^\s)]+")

# Hashtags
HASHTAG_REGEX = re.compile(r"#[A-Za-z]\w*")

# STEP 5: Extra validation helpers to avoid false positives

def looks_like_phone_not_card(number_digits):

    return len(number_digits) < 13 or len(number_digits) > 19

# STEP 6: Process a single ticket and pull out all the data types

def extract_from_ticket(ticket_text, ticket_index):
    result = {
        "ticket_number": ticket_index,
        "status": "safe",
        "emails": [],
        "credit_cards": [],
        "phone_numbers": [],
        "urls": [],
        "hashtags": [],
    }

    if is_suspicious(ticket_text):
        result["status"] = "rejected_unsafe_input"
        return result

    # Emails
    for email in EMAIL_REGEX.findall(ticket_text):
        result["emails"].append({
            "value": email,
            "category": classify_email(email),
        })

    # Credit cards
    text_without_cards = ticket_text
    for match in CREDIT_CARD_REGEX.findall(ticket_text):
        digits_only = re.sub(r"[ -]", "", match)
        if looks_like_phone_not_card(digits_only):
            continue
        if luhn_checksum(digits_only):
            result["credit_cards"].append({
                "masked_value": mask_card(match),
                "luhn_valid": True,
            })

            text_without_cards = text_without_cards.replace(match, " " * len(match))

    # Phone numbers
    for phone in PHONE_REGEX.findall(text_without_cards):
        digits_only = re.sub(r"[^\d]", "", phone)
        if 13 <= len(digits_only) <= 19:
            continue
        if len(digits_only) >= 7:
            result["phone_numbers"].append(phone.strip())

    # URLs 
    result["urls"] = URL_REGEX.findall(ticket_text)

    # Hashtags
    result["hashtags"] = HASHTAG_REGEX.findall(ticket_text)

    return result

# STEP 7: Print a friendly summary to the console

def print_summary(all_results):
    print("=" * 65)
    print("DATA EXTRACTION SUMMARY")
    print("=" * 65)

    for ticket in all_results:
        print(f"\nTicket #{ticket['ticket_number']}  -  Status: {ticket['status']}")

        if ticket["status"] == "rejected_unsafe_input":
            print("  This ticket was REJECTED because it contained suspicious")
            print("  or potentially malicious content. No data was extracted.")
            continue

        if ticket["emails"]:
            print("  Emails found:")
            for e in ticket["emails"]:
                print(f"    - {e['value']}  ({e['category']})")

        if ticket["credit_cards"]:
            print("  Credit cards found (masked for safety):")
            for c in ticket["credit_cards"]:
                print(f"    - {c['masked_value']}")

        if ticket["phone_numbers"]:
            print("  Phone numbers found:")
            for p in ticket["phone_numbers"]:
                print(f"    - {p}")

        if ticket["urls"]:
            print("  URLs found:")
            for u in ticket["urls"]:
                print(f"    - {u}")

        if ticket["hashtags"]:
            print("  Hashtags found:")
            for h in ticket["hashtags"]:
                print(f"    - {h}")

    print("\n" + "=" * 65)
    total_safe = sum(1 for t in all_results if t["status"] == "safe")
    total_rejected = sum(1 for t in all_results if t["status"] != "safe")
    print(f"Total tickets processed: {len(all_results)}")
    print(f"Safe tickets: {total_safe}")
    print(f"Rejected (unsafe) tickets: {total_rejected}")
    print("=" * 65)


# STEP 8: Saving the results as JSON so it can be reused by other programs
def save_json(all_results, output_path):
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(all_results, file, indent=2)

# STEP 9: Tie everything together
def main():
    input_path = os.path.join("input", "raw-text.txt")
    output_path = os.path.join("output", "sample-output.json")

    if not os.path.exists(input_path):
        print("Input file not found. A built-in example dataset will be used instead.")

    raw_text = read_input_file(input_path)
    tickets = split_into_tickets(raw_text)

    all_results = []
    for index, ticket_text in enumerate(tickets, start=1):
        extracted = extract_from_ticket(ticket_text, index)
        all_results.append(extracted)

    print_summary(all_results)
    save_json(all_results, output_path)
    print(f"\nFull structured results saved to: {output_path}")


if __name__ == "__main__":
    main()

