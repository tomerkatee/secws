import http_traffic_scraper
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import random
import re


symbols = ['+', '-', '*', '/', '%', '=', '+=', '-=', '*=', '/=', '%=', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!', '&', '<<', '>>', ';', ',', '.', '->', '[', ']', '(', ')', '{', '}', '#']

types = ['int', 'char', 'float', 'double', 'void', 'long', 'short']

keywords = [
    'static', 'extern',   # Storage class specifiers
    'break', 'continue', 'return', 'goto',   # Control flow keywords
    'const',  # Type qualifiers
    'sizeof', 'typedef', 'enum', 'struct',  # Miscellaneous keywords
]

c_patterns = {
    'if_statement': r'if\s*\([^)]*\)\s*{',
    'else_statement': r'else\s*{',
    'while_statement': r'while\s*\([^)]*\)\s*{',
    'do_statement': r'do\s*{',
    'switch_statement': r'switch\s*\([^)]*\)\s*{[^{}]*}',
    'case_label': r'case\s+[^:]+:',
    'default_label': r'default\s*:',
    'function_declaration': r'(?:int|void|double|float)\s+\w+\s*\([^)]*\)\s*',
    'struct_declaration': r'struct\s+[A-Za-z_][A-Za-z0-9_]*\s*{[^{}]*};',
    'typedef_declaration': r'typedef\s+.*?;',
    'macro_definition': r'#define\s+\w+\s+.*',
    'comment': r'(\/\/.*$|\/\*[\s\S]*?\*\/)',  # Matches single-line and multi-line comments
}

MIN_STR_SIZE = 100
TEST_RATIO = 0.2
C_SCAN_CHUNK_SIZE = 200


def split_to_chunks(s):
    chunks = []
    for i in range(0, len(s)//C_SCAN_CHUNK_SIZE+1):
        chunks.append(s[i*C_SCAN_CHUNK_SIZE:(i+1)*C_SCAN_CHUNK_SIZE])

    return chunks


# makes frequency vectors out of the data in the given files, and then builds a random forest with sklearn
def train(regular_traffic_file, c_code_file="c_code.txt"):
    print("Training model...")

    regular_traffic = http_traffic_scraper.scrape_traffic(regular_traffic_file)

    with open(c_code_file, 'r') as file:
        c_code_lines = file.readlines()
    programs = split_into_programs(c_code_lines)

    c_chunks = [c for p in programs for c in split_to_chunks(p)]
    regular_traffic_chunks = [c for r in regular_traffic for c in split_to_chunks(r)]

    regular_traffic_vectors = [list(token_fracs(r).values()) for r in regular_traffic_chunks]
    programs_vectors = [list(token_fracs(p).values()) for p in c_chunks]

    random.shuffle(regular_traffic_vectors)
    random.shuffle(programs_vectors)
    
    end_test_prog = int(len(programs_vectors)*TEST_RATIO)
    end_test_reg = int(len(regular_traffic_vectors)*TEST_RATIO)

    Y_reg = [0 for _ in regular_traffic_vectors]
    
    Y_prog = [1 for _ in programs_vectors]

    X_train = regular_traffic_vectors[end_test_reg:] + programs_vectors[end_test_prog:]
    Y_train = Y_reg[end_test_reg:] + Y_prog[end_test_prog:]

    X_test = regular_traffic_vectors[:end_test_reg] + programs_vectors[:end_test_prog]
    Y_test = Y_reg[:end_test_reg] + Y_prog[:end_test_prog]

    clf = RandomForestClassifier(n_estimators=100, random_state=42)

    clf = clf.fit(X_train, Y_train)

    Y_pred = clf.predict(X_test)

    print("Accuracy:", accuracy_score(Y_test, Y_pred))

    return clf


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


# returns a dictionary containing frequencies of common patterns, symbols, keywords and types.
def token_fracs(s: str):
    res = {}

    for k, v in c_patterns.items():
        res[k] = len(re.findall(v, s)) / len(s) if len(s) else 0

    for t in symbols+keywords+types:
        res[t] = s.count(t) / len(s) if len(s) else 0

    return res


# scans a string for C code, does it by checking one chunk at a time
def contains_c_code(clf, data):
    is_c_code = lambda msg: len(msg) > MIN_STR_SIZE and clf.predict([list(token_fracs(msg).values())])[0] == 1

    for chunk in split_to_chunks(data):
        if is_c_code(chunk):
            print("this chunk is c code: " + chunk)
            return True

    return False