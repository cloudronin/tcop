#!/usr/bin/env python3
from paperlib import page_budget

if __name__ == "__main__":
    import json
    print(json.dumps(page_budget(), indent=2, sort_keys=True))
