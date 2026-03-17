import json
import os

CACHE_FOLDER = "cache"


def get_cache(cve_id):

    file_path = os.path.join(CACHE_FOLDER, f"{cve_id}.json")

    if os.path.exists(file_path):

        with open(file_path, "r") as f:
            return json.load(f)

    return None


def save_cache(cve_id, data):

    file_path = os.path.join(CACHE_FOLDER, f"{cve_id}.json")

    with open(file_path, "w") as f:
        json.dump(data, f)
