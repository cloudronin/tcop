#!/usr/bin/env python3
from paperlib import main

if __name__ == "__main__":
    import sys
    sys.argv[1:] = ["figures", *sys.argv[1:]]
    main()
