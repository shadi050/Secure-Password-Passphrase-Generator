import secrets
import string
import argparse
import math
import csv
import json
from datetime import datetime
import sys



LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}"

WORD_LIST = [
    "secure", "network", "cipher", "python", "hash", "token",
    "firewall", "packet", "crypto", "entropy", "access", "system",
    "protocol", "identity", "authentication", "authorization",
    "confidential", "integrity", "availability", "certificate"
]

MIN_PASSWORD_LENGTH = 12
MIN_PASSPHRASE_WORDS = 4



def generate_password(length, charset):
    return "".join(secrets.choice(charset) for _ in range(length))


def generate_passphrase(num_words, separator="-"):
    return separator.join(secrets.choice(WORD_LIST) for _ in range(num_words))


def calculate_entropy(length, charset_size):
    if charset_size <= 1:
        return 0.0
    return round(length * math.log2(charset_size), 2)


def evaluate_strength(entropy):
    if entropy < 40:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"


def export_csv(filename, data):
    if not data:
        return
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


def export_json(filename, data):
    if not data:
        return
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)




def ask_yes_no(prompt):
    while True:
        choice = input(f"{prompt} [y/n]: ").strip().lower()
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        print("Please enter y or n.")


def interactive_config():
    print("\n=== Interactive Password Generator ===\n")

    use_passphrase = ask_yes_no("Generate passphrase instead of password?")

    if use_passphrase:
        words = int(input(f"Number of words (min {MIN_PASSPHRASE_WORDS}): "))
        number = int(input("How many passphrases to generate?: "))
        export = input("Export format (csv/json/none): ").strip().lower()
        export = export if export in ("csv", "json") else None

        return {
            "passphrase": True,
            "words": words,
            "number": number,
            "export": export
        }

    length = int(input(f"Password length (min {MIN_PASSWORD_LENGTH}): "))
    number = int(input("How many passwords to generate?: "))

    lower = ask_yes_no("Include lowercase letters?")
    upper = ask_yes_no("Include uppercase letters?")
    digits = ask_yes_no("Include digits?")
    symbols = ask_yes_no("Include symbols?")

    export = input("Export format (csv/json/none): ").strip().lower()
    export = export if export in ("csv", "json") else None

    return {
        "passphrase": False,
        "length": length,
        "number": number,
        "lower": lower,
        "upper": upper,
        "digits": digits,
        "symbols": symbols,
        "export": export
    }




def main():
    parser = argparse.ArgumentParser(
        description="Secure Password & Passphrase Generator"
    )

    parser.add_argument("-l", "--length", type=int, default=16)
    parser.add_argument("-n", "--number", type=int, default=1)

    parser.add_argument("--lower", action="store_true")
    parser.add_argument("--upper", action="store_true")
    parser.add_argument("--digits", action="store_true")
    parser.add_argument("--symbols", action="store_true")

    parser.add_argument("--passphrase", action="store_true")
    parser.add_argument("--words", type=int, default=4)

    parser.add_argument("--export", choices=["csv", "json"])

    args = parser.parse_args()

    if len(sys.argv) == 1:
        config = interactive_config()
    else:
        config = vars(args)

    results = []
    generated_values = set()

    if config.get("passphrase"):
        if config["words"] < MIN_PASSPHRASE_WORDS:
            sys.exit(f"[ERROR] Passphrase must contain at least {MIN_PASSPHRASE_WORDS} words")

        charset_size = len(WORD_LIST)
        if charset_size < 2048:
            print("[WARNING] Small wordlist reduces passphrase security")

        while len(results) < config["number"]:
            phrase = generate_passphrase(config["words"])
            if phrase in generated_values:
                continue

            generated_values.add(phrase)
            entropy = calculate_entropy(config["words"], charset_size)

            results.append({
                "value": phrase,
                "entropy_bits": entropy,
                "strength": evaluate_strength(entropy)
            })

    else:
        if config["length"] < MIN_PASSWORD_LENGTH:
            sys.exit(f"[ERROR] Password length must be at least {MIN_PASSWORD_LENGTH}")

        charset = ""
        if config.get("lower"):
            charset += LOWERCASE
        if config.get("upper"):
            charset += UPPERCASE
        if config.get("digits"):
            charset += DIGITS
        if config.get("symbols"):
            charset += SYMBOLS

        if not charset:
            charset = LOWERCASE + UPPERCASE + DIGITS

        charset_size = len(charset)

        while len(results) < config["number"]:
            pwd = generate_password(config["length"], charset)
            if pwd in generated_values:
                continue

            generated_values.add(pwd)
            entropy = calculate_entropy(config["length"], charset_size)

            results.append({
                "value": pwd,
                "entropy_bits": entropy,
                "strength": evaluate_strength(entropy)
            })

    print("\nGenerated Credentials:\n")
    for item in results:
        print(item)

    if config.get("export"):
        filename = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{config['export']}"
        export_csv(filename, results) if config["export"] == "csv" else export_json(filename, results)
        print(f"\nResults exported to {filename}")


if __name__ == "__main__":
    main()
