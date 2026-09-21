import sys

with open('src/graph/cypher_builder.py', 'r', encoding='utf-8') as f:
    text = f.read()
    
# Split by lines
lines = text.split('\n')
for i, line in enumerate(lines):
    if '"""' in line:
        print(f"{i+1}: {line}")
