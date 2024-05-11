import response_scraper
import sys
import re

symbols = [
    '+', '-', '*', '/', '%',   # Arithmetic operators
    '=', '+=', '-=', '*=', '/=', '%=',   # Assignment operators
    '==', '!=', '<', '>', '<=', '>=',   # Comparison operators
    '&&', '||', '!',   # Logical operators
    '&', '|', '^', '~', '<<', '>>',   # Bitwise operators
    ';', ',', '.', '->', '[', ']', '(', ')', '{', '}', '#',   # Other symbols
]

keywords = [
    'auto', 'register', 'static', 'extern',   # Storage class specifiers
    'int', 'char', 'float', 'double', 'void', 'long', 'short', '_Bool', '_Complex', '_Imaginary',   # Data type specifiers
    'if', 'else', 'switch', 'case', 'default', 'while', 'do', 'for', 'break', 'continue', 'return', 'goto',   # Control flow keywords
    'inline',   # Function specifiers
    'const', 'volatile', 'restrict',   # Type qualifiers
    'sizeof', 'typedef', 'enum', 'struct', 'union',   # Miscellaneous keywords
]

MIN_STR_SIZE = 30

def train(strs: list):
    pass

def main():
    HTTP_regular_responses = response_scraper.scrape_responses(sys.argv[1])
    HTTP_regular_responses = [s for s in HTTP_regular_responses if len(s) >= MIN_STR_SIZE]
    with open("demo.txt", 'r') as file:
        C_code = file.read()


    pattern = r'(#include.*\n)+^(?!#include)'
    programs = re.split(pattern, C_code, flags=re.MULTILINE)

    for idx, program in enumerate(programs[:6], start=1):
        print(idx)
        print(program)


if __name__ == "__main__":
    main()