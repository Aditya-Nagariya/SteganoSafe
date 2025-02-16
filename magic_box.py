import re
import math

def tokenize(text):
    # Extract words from text, converting to lowercase.
    return re.findall(r'\w+', text.lower())

def cosine_similarity(tokens_a, tokens_b):
    # Build frequency dictionaries for both token lists.
    vec_a = {}
    vec_b = {}
    for t in tokens_a:
        vec_a[t] = vec_a.get(t, 0) + 1
    for t in tokens_b:
        vec_b[t] = vec_b.get(t, 0) + 1
    common = set(vec_a.keys()) & set(vec_b.keys())
    score = sum(vec_a[t] * vec_b[t] for t in common)
    mag_a = math.sqrt(sum(val * val for val in vec_a.values()))
    mag_b = math.sqrt(sum(val * val for val in vec_b.values()))
    return score / (mag_a * mag_b) if mag_a and mag_b else 0

def detect_suspicious(log_lines, reference_words=('error', 'unauthorized', 'failed')):
    # Iterate each line and if similarity with any reference word is >0, consider it suspicious.
    suspects = []
    for line in log_lines:
        tokens = tokenize(line)
        for ref in reference_words:
            if cosine_similarity(tokens, tokenize(ref)) > 0:
                suspects.append(line.strip())
                break
    return suspects