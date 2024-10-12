#!/usr/bin/env python3
"""
Example usage: python3 /path/to/0a7e8bda-3585-4867-9007-343db0f236bd.bin
"""
import sys
from pprint import pprint
from dataclasses import asdict
from main import TabStateParser

def main():
	tsp = TabStateParser(sys.argv[1])
	file_struct = tsp.parse()
	pprint(asdict(file_struct))

if __name__ == "__main__":
	main()