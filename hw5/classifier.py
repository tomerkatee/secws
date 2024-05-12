import response_scraper
import sys
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import export_graphviz
from sklearn.metrics import accuracy_score
import random
import subprocess





all_symbol_names = {
    '+': 'plus',
    '-': 'minus',
    '*': 'asterisk',
    '/': 'slash',
    '%': 'percent',
    '=': 'equals',
    '+=': 'plus_equals',
    '-=': 'minus_equals',
    '*=': 'times_equals',
    '/=': 'divide_equals',
    '%=': 'mod_equals',
    '==': 'equals_equals',
    '!=': 'not_equals',
    '<': 'less_than',
    '>': 'greater_than',
    '<=': 'less_than_or_equal',
    '>=': 'greater_than_or_equal',
    '&&': 'logical_and',
    '||': 'logical_or',
    '!': 'logical_not',
    '&': 'bitwise_and',
    '|': 'bitwise_or',
    '^': 'bitwise_xor',
    '~': 'bitwise_not',
    '<<': 'left_shift',
    '>>': 'right_shift',
    ';': 'semicolon',
    ',': 'comma',
    '.': 'dot',
    '->': 'arrow',
    '[': 'left_square_bracket',
    ']': 'right_square_bracket',
    '(': 'left_parenthesis',
    ')': 'right_parenthesis',
    '{': 'left_curly_bracket',
    '}': 'right_curly_bracket',
    '#': 'hash',
}


symbol_names = {
    '+': 'plus',
    '-': 'minus',
    '*': 'asterisk',
    '/': 'slash',
    '%': 'percent',
    '=': 'equals',
    '+=': 'plus_equals',
    '-=': 'minus_equals',
    '*=': 'times_equals',
    '/=': 'divide_equals',
    '%=': 'mod_equals',
    '==': 'equals_equals',
    '!=': 'not_equals',
    '<': 'less_than',
    '>': 'greater_than',
    '<=': 'less_than_or_equal',
    '>=': 'greater_than_or_equal',
    '&&': 'logical_and',
    '||': 'logical_or',
    '!': 'logical_not',
    '&': 'bitwise_and',
    '<<': 'left_shift',
    '>>': 'right_shift',
    ';': 'semicolon',
    ',': 'comma',
    '.': 'dot',
    '->': 'arrow',
    '[': 'left_square_bracket',
    ']': 'right_square_bracket',
    '(': 'left_parenthesis',
    ')': 'right_parenthesis',
    '{': 'left_curly_bracket',
    '}': 'right_curly_bracket',
    '#': 'hash',
}

keywords = [
    'static', 'extern',   # Storage class specifiers
    'int', 'char', 'float', 'double', 'void', 'long', 'short',  # Data type specifiers
    'if', 'else', 'switch', 'case', 'while', 'do', 'for', 'break', 'continue', 'return', 'goto',   # Control flow keywords
    'const',  # Type qualifiers
    'sizeof', 'typedef', 'enum', 'struct',  # Miscellaneous keywords
]

all_keywords = [
    'auto', 'register', 'static', 'extern',   # Storage class specifiers
    'int', 'char', 'float', 'double', 'void', 'long', 'short', '_Bool', '_Complex', '_Imaginary',   # Data type specifiers
    'if', 'else', 'switch', 'case', 'default', 'while', 'do', 'for', 'break', 'continue', 'return', 'goto',   # Control flow keywords
    'inline',   # Function specifiers
    'const', 'volatile', 'restrict',   # Type qualifiers
    'sizeof', 'typedef', 'enum', 'struct', 'union',   # Miscellaneous keywords
]

MIN_STR_SIZE = 30
TEST_RATIO = 0.2

def train(strs: list):
    pass


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


def token_fracs_truncated(s: str):
    res = {}
    for t in list(symbol_names.keys())+keywords:
        res[t] = s.count(t) / len(s)


    return res


def main():
    HTTP_regular_responses = response_scraper.scrape_responses(sys.argv[1])
    # filter by size
    HTTP_regular_responses = [s for s in HTTP_regular_responses if len(s) >= MIN_STR_SIZE]

    with open("c_code.txt", 'r') as file:
        c_code_lines = file.readlines()
    programs = split_into_programs(c_code_lines)

    HTTP_regular_responses_vectors = [list(token_fracs_truncated(r).values()) for r in HTTP_regular_responses]
    programs_vectors = [list(token_fracs_truncated(p).values()) for p in programs]
            

    random.shuffle(HTTP_regular_responses_vectors)
    random.shuffle(programs_vectors)
    
    end_test_prog = int(len(programs_vectors)*TEST_RATIO)
    end_test_reg = int(len(HTTP_regular_responses_vectors)*TEST_RATIO)

    Y_reg = [0 for _ in HTTP_regular_responses_vectors]
    
    Y_prog = [1 for _ in programs_vectors]

    X_train = HTTP_regular_responses_vectors[end_test_reg:] + programs_vectors[end_test_prog:]
    Y_train = Y_reg[end_test_reg:] + Y_prog[end_test_prog:]

    X_test = HTTP_regular_responses_vectors[:end_test_reg] + programs_vectors[:end_test_prog]
    Y_test = Y_reg[:end_test_reg] + Y_prog[:end_test_prog]

    clf = RandomForestClassifier(n_estimators=100, random_state=42)

    clf = clf.fit(X_train, Y_train)

    Y_pred = clf.predict(X_test)

    print("Accuracy:", accuracy_score(Y_test, Y_pred))


    with open("test.txt", 'r') as file:
        print(clf.predict([list(token_fracs_truncated(file.read()).values())]))


    export_graphviz(clf.estimators_[0], out_file='tree.dot', 
                    feature_names=list(symbol_names.values())+keywords,  
                    class_names=['not C', 'C'],  
                    filled=True, rounded=True,  
                    special_characters=True)

    subprocess.call(['dot', '-Tpng', 'tree.dot', '-o', 'classification_tree.png'])


if __name__ == "__main__":
    main()