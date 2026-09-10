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

CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_checksum(card_number):
    """
    The Luhn algorithm is the standard checksum used by real credit cards
    to catch typos. We use it here to double-check that a number we matched
    is at least *structurally* plausible as a real card, not just any
    13-19 digit number (like a phone number or an ID).
    """
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
    """
    SECURITY: we never expose a full card number in our output or logs.
    We only keep the last 4 digits, matching real-world best practice.
    """
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


def looks_like_phone_not_card(number_digits):
    """
    Some short digit groups can accidentally match both the phone and card
    patterns. We only treat something as a credit card if it has 13-19
    digits AND passes the Luhn check. Otherwise we leave it for the phone
    regex to (maybe) pick up.
    """
    return len(number_digits) < 13 or len(number_digits) > 19

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


def save_json(all_results, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(all_results, file, indent=2)

def main():
    input_path = os.path.join("input", "raw-text.txt")
    output_path = os.path.join("output", "sample-output.json")

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
