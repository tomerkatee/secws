import response_scraper
import sys
import sklearn


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

def tokenize(s: str):
    res = {}
    for t in symbols+keywords:
        res[t] = s.count(t)

    return res

def split_into_programs(c_code_lines):

    programs = []
    in_includes = True
    curr = ""
    for l in c_code_lines:
        if "#include" in l and not in_includes:
            programs.append(curr)
            in_includes = True
            curr = ""
        elif in_includes and not l.startswith('#include'):
            in_includes = False

        curr += l
    
    programs.append(curr)

    return programs


def main():
    HTTP_regular_responses = response_scraper.scrape_responses(sys.argv[1])
    # filter by size
    HTTP_regular_responses = [s for s in HTTP_regular_responses if len(s) >= MIN_STR_SIZE]


    with open("c_code.txt", 'r') as file:
        c_code_lines = file.readlines()
    
    programs = split_into_programs(c_code_lines)

    vectors


    


if __name__ == "__main__":
    main()