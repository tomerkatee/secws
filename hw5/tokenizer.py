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


def main():
    train()


if __name__ == "__main__":
    main()