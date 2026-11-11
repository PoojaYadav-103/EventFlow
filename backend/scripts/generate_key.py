import sys
from cryptography.fernet import Fernet


def main():
    key = Fernet.generate_key().decode("utf-8")
    print("=== EventFlow Fernet Encryption Key Generator ===")
    print(f"Generated Key: {key}")
    print("\nTo configure EventFlow with this key:")
    print(f"1. Add to your .env file:")
    print(f"   ENCRYPTION_KEY={key}")
    print(f"2. Or export in your shell:")
    print(f"   export ENCRYPTION_KEY={key}")


if __name__ == "__main__":
    main()
