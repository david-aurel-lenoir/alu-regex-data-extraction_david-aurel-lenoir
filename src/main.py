import json, os, re

DEFAULT_RAW_TEXT = '''---
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
'''

SUSPICIOUS = re.compile(r"<script.*?>|on\w+\s*=\s*['\"]?|drop\s+table|--\s*$|';.*--|<img[^>]*onerror", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
ALU_OFFICIAL = re.compile(r"@alueducation\.com$", re.I)
ALU_ALUMNI = re.compile(r"@alumni\.alueducation\.com$", re.I)
ALU_SI = re.compile(r"@si\.alueducation\.com$", re.I)
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
PHONE = re.compile(r"(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{2,4}(?:[ -]\d{3,4}){1,3}")
URL = re.compile(r"https?://[^\s)]+")
HASHTAG = re.compile(r"#[A-Za-z]\w*")

def read_input_file(filepath):
    if not os.path.exists(filepath):
        alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input", "raw-text.txt")
        if os.path.exists(alt):
            filepath = alt
        else:
            return DEFAULT_RAW_TEXT
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()

def split_into_tickets(raw_text):
    return [t.strip() for t in re.split(r"\n-{3,}\n", raw_text) if t.strip()]

def is_suspicious(text):
    return bool(SUSPICIOUS.search(text))

def classify_email(email):
    if ALU_ALUMNI.search(email): return "ALU Alumni"
    if ALU_SI.search(email): return "ALU SI (School of ...)"
    if ALU_OFFICIAL.search(email): return "ALU Official"
    return "External / Personal"

def luhn(card_number):
    digits = [int(d) for d in card_number][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        total += d
    return total % 10 == 0

def mask_card(card_number):
    digits_only = re.sub(r"[ -]", "", card_number)
    return "**** **** **** " + digits_only[-4:]

def extract_from_ticket(ticket_text, ticket_index):
    result = {"ticket_number": ticket_index, "status": "safe", "emails": [], "credit_cards": [], "phone_numbers": [], "urls": [], "hashtags": []}
    if is_suspicious(ticket_text):
        result["status"] = "rejected_unsafe_input"
        return result
    for email in EMAIL.findall(ticket_text):
        result["emails"].append({"value": email, "category": classify_email(email)})
    clean_ticket = ticket_text
    for match in CARD.findall(ticket_text):
        digits_only = re.sub(r"[ -]", "", match)
        if len(digits_only) < 13 or len(digits_only) > 19: continue
        if luhn(digits_only):
            result["credit_cards"].append({"masked_value": mask_card(match), "luhn_valid": True})
            clean_ticket = clean_ticket.replace(match, " " * len(match))
    for phone in PHONE.findall(clean_ticket):
        digits_only = re.sub(r"\D", "", phone)
        if 13 <= len(digits_only) <= 19 or len(digits_only) < 7: continue
        result["phone_numbers"].append(phone.strip())
    result["urls"] = URL.findall(ticket_text)
    result["hashtags"] = HASHTAG.findall(ticket_text)
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
            for e in ticket["emails"]: print(f"    - {e['value']}  ({e['category']})")
        if ticket["credit_cards"]:
            print("  Credit cards found (masked for safety):")
            for c in ticket["credit_cards"]: print(f"    - {c['masked_value']}")
        if ticket["phone_numbers"]:
            print("  Phone numbers found:")
            for p in ticket["phone_numbers"]: print(f"    - {p}")
        if ticket["urls"]:
            print("  URLs found:")
            for u in ticket["urls"]: print(f"    - {u}")
        if ticket["hashtags"]:
            print("  Hashtags found:")
            for h in ticket["hashtags"]: print(f"    - {h}")
    total_safe = sum(1 for t in all_results if t["status"] == "safe")
    total_rejected = sum(1 for t in all_results if t["status"] != "safe")
    print(f"\nTotal tickets processed: {len(all_results)}")
    print(f"Safe tickets: {total_safe}")
    print(f"Rejected (unsafe) tickets: {total_rejected}")
    print("=" * 65)

def save_json(all_results, output_path):
    directory = os.path.dirname(output_path)
    if directory: os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f: json.dump(all_results, f, indent=2)

def main():
    input_path = os.path.join("input", "raw-text.txt")
    output_path = os.path.join("output", "sample-output.json")
    if not os.path.exists(input_path):
        print("Input file not found. A built-in example dataset will be used instead.")
    all_results = [extract_from_ticket(ticket, i + 1) for i, ticket in enumerate(split_into_tickets(read_input_file(input_path)))]
    print_summary(all_results)
    save_json(all_results, output_path)
    print(f"\nFull structured results saved to: {output_path}")

if __name__ == "__main__": main()
