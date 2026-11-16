"""Byte-oriented helpers for forensic_harvester; no game code is executed."""
from collections import Counter
import hashlib
import math
import re


def masked_pattern(text):
    tokens = text.split()
    if not tokens or len(tokens) > 4096:
        raise ValueError('Pattern must contain 1 to 4096 space-separated bytes')
    pattern = []
    for token in tokens:
        if token in ('?', '??'):
            pattern.append(None)
        elif re.fullmatch(r'[0-9a-fA-F]{2}', token):
            pattern.append(int(token, 16))
        else:
            raise ValueError('Pattern tokens must be hex bytes or ??')
    return pattern


def pattern_offsets(data, pattern):
    """Find overlapping byte-pattern matches without crossing the buffer."""
    size = len(pattern)
    if not size:
        raise ValueError('Pattern must not be empty')
    if size > len(data):
        return
    # Anchor at the longest contiguous literal sequence; if all bytes are
    # wildcards, every complete window matches. Verification handles overlaps.
    runs = []
    i = 0
    while i < size:
        if pattern[i] is None:
            i += 1
            continue
        start = i
        while i < size and pattern[i] is not None:
            i += 1
        runs.append((start, bytes(pattern[start:i])))
    if not runs:
        yield from range(len(data) - size + 1)
        return
    anchor_pos, anchor = max(runs, key=lambda x: len(x[1]))
    start = 0
    while True:
        found = data.find(anchor, start)
        if found < 0:
            break
        start = found + 1
        pos = found - anchor_pos
        if pos < 0 or pos + size > len(data):
            continue
        if all(value is None or data[pos + j] == value for j, value in enumerate(pattern)):
            yield pos


def string_hits(data, encoding, minimum, contains=None, nul_only=False):
    """ASCII-range printable runs, or ASCII-range characters in UTF-16."""
    if minimum < 1:
        raise ValueError('Minimum string length must be positive')
    unit = {'ascii': rb'[\x20-\x7e]', 'utf-16le': rb'[\x20-\x7e]\x00',
            'utf-16be': rb'\x00[\x20-\x7e]'}[encoding]
    regex = re.compile(b'(?:' + unit + b'){' + str(minimum).encode('ascii') + b',}')
    width = 1 if encoding == 'ascii' else 2
    needle = contains.casefold() if contains is not None else None
    for match in regex.finditer(data):
        start, end = match.span()
        terminated = data[end:end + width] == b'\0' * width
        if nul_only and not terminated:
            continue
        raw = match.group()
        text = raw.decode(encoding)
        if needle is not None and needle not in text.casefold():
            continue
        yield {'offset': start, 'byte_length': len(raw), 'characters': len(text),
               'nul_terminated': terminated, 'reaches_section_end': end == len(data),
               'text_preview': text[:512], 'preview_truncated': len(text) > 512,
               'content_sha256': hashlib.sha256(raw).hexdigest()}


def statistics(data):
    n = len(data)
    counts = Counter(data)
    entropy = -sum((count / n) * math.log2(count / n) for count in counts.values()) if n else 0.0
    longest_zero = max((len(m.group()) for m in re.finditer(rb'\x00+', data)), default=0)
    printable = sum(counts.get(x, 0) for x in range(0x20, 0x7f))
    return {'raw_bytes': n, 'sha256': hashlib.sha256(data).hexdigest(), 'entropy_bits_per_byte': round(entropy, 6),
            'zero_bytes': counts.get(0, 0), 'zero_fraction': round(counts.get(0, 0) / n, 6) if n else 0.0,
            'longest_zero_run': longest_zero, 'printable_ascii_bytes': printable,
            'printable_ascii_fraction': round(printable / n, 6) if n else 0.0,
            'distinct_byte_values': len(counts)}
