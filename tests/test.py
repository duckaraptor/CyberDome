import os
import sys

# Make the repo root importable, wherever this script is started from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cyberdome.trust_algorithm as ta

# Calculate overall trust score for a specific user_id, e.g.
#   python3 tests/test.py 91e69d52-52ac-4e33-971b-62cf0542f4ba
if len(sys.argv) != 2:
    sys.exit("Usage: python3 tests/test.py <keycloak user id>")

user_id = sys.argv[1]
trust_score = ta.calculate_overall_trust_score(user_id)
print(f"Overall Trust Score for user ID {user_id}: {trust_score}")
