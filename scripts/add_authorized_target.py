"""
Usage: python add_authorized_target.py seatsip.com "own site, testing active tier"
"""
import sys
import datetime
from pymongo import MongoClient

def main():
    if len(sys.argv) < 2:
        print("Usage: python add_authorized_target.py <hostname> [note]")
        sys.exit(1)

    hostname = sys.argv[1]
    note = sys.argv[2] if len(sys.argv) > 2 else ""

    db = MongoClient("mongodb://localhost:27017")["specula"]
    db["authorized_targets"].update_one(
        {"target": hostname},
        {"$set": {"target": hostname, "note": note, "added_at": datetime.datetime.utcnow()}},
        upsert=True,
    )
    print(f"Authorized: {hostname}")

if __name__ == "__main__":
    main()
