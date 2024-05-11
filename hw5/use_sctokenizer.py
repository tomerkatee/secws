import sctokenizer

tokens = sctokenizer.tokenize_file(filepath='test.cpp', lang='cpp')
for token in tokens:
    print(token)