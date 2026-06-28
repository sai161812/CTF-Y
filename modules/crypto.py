import base64
import binascii
import string
import math
from collections import Counter
from itertools import cycle


# ──────────────────────────────────────────────────────────────────────────────
# Encoding / decoding
# ──────────────────────────────────────────────────────────────────────────────

def try_all_encodings(data: str) -> dict:
    """Try every common encoding and return successful decodings."""
    results = {}

    # Base64
    try:
        padded = data + "=" * (-len(data) % 4)
        results["base64"] = base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base64 URL-safe
    try:
        padded = data.replace("-", "+").replace("_", "/") + "=" * (-len(data) % 4)
        results["base64url"] = base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base32
    try:
        padded = data.upper() + "=" * (-len(data) % 8)
        results["base32"] = base64.b32decode(padded).decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base85
    try:
        results["base85"] = base64.b85decode(data).decode("utf-8", errors="replace")
    except Exception:
        pass

    # Hex
    try:
        cleaned = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        results["hex"] = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception:
        pass

    # ROT13
    results["rot13"] = data.translate(
        str.maketrans(
            string.ascii_uppercase + string.ascii_lowercase,
            string.ascii_uppercase[13:] + string.ascii_uppercase[:13]
            + string.ascii_lowercase[13:] + string.ascii_lowercase[:13],
        )
    )

    # Binary string (e.g. "01100110 01101100 01100001 01100111")
    binary_cleaned = data.replace(" ", "")
    if all(c in "01" for c in binary_cleaned) and len(binary_cleaned) % 8 == 0:
        try:
            results["binary"] = "".join(
                chr(int(binary_cleaned[i: i + 8], 2))
                for i in range(0, len(binary_cleaned), 8)
            )
        except Exception:
            pass

    # Decimal list (e.g. "102 108 97 103")
    parts = data.split()
    if all(p.isdigit() for p in parts):
        try:
            results["decimal_list"] = "".join(chr(int(p)) for p in parts if 0 < int(p) < 128)
        except Exception:
            pass

    # Octal
    try:
        if all(c in "01234567 " for c in data):
            results["octal"] = "".join(chr(int(o, 8)) for o in data.split())
    except Exception:
        pass

    return {k: v for k, v in results.items() if v}


# ──────────────────────────────────────────────────────────────────────────────
# Classical ciphers
# ──────────────────────────────────────────────────────────────────────────────

def caesar_brute(ciphertext: str) -> list[tuple[int, str]]:
    """Return all 25 Caesar shifts."""
    results = []
    for shift in range(1, 26):
        decoded = []
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                decoded.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                decoded.append(ch)
        results.append((shift, "".join(decoded)))
    return results


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    decoded = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            decoded.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            decoded.append(ch)
    return "".join(decoded)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = key.upper()
    result = []
    k = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[k % len(key)]) - ord("A")
            result.append(chr((ord(ch.upper()) - ord("A") - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_kasiski(ciphertext: str, max_keylen: int = 20) -> list[int]:
    """Estimate Vigenere key length using index of coincidence."""
    text = [c.upper() for c in ciphertext if c.isalpha()]
    best = []
    for keylen in range(2, max_keylen + 1):
        avg_ic = 0.0
        for offset in range(keylen):
            sub = text[offset::keylen]
            n = len(sub)
            if n < 2:
                continue
            freq = Counter(sub)
            ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
            avg_ic += ic
        avg_ic /= keylen
        if avg_ic > 0.06:   # English IC ≈ 0.065
            best.append((keylen, avg_ic))
    best.sort(key=lambda x: -x[1])
    return [k for k, _ in best[:5]]


def atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return "".join(result)


def rot_n(text: str, n: int) -> str:
    return caesar_decrypt(text, -n % 26)


def substitution_auto(ciphertext: str) -> tuple[str, dict]:
    """
    Frequency-analysis substitution solver.
    Returns (decrypted_guess, mapping).
    """
    ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    freq = Counter(letters)
    cipher_order = [c for c, _ in freq.most_common()]
    mapping = {c: ENGLISH_FREQ[i] if i < 26 else "?" for i, c in enumerate(cipher_order)}
    result = []
    for ch in ciphertext:
        if ch.lower() in mapping:
            m = mapping[ch.lower()]
            result.append(m.upper() if ch.isupper() else m)
        else:
            result.append(ch)
    return "".join(result), mapping


def morse_decode(morse: str) -> str:
    TABLE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9", "/": " ",
    }
    return "".join(TABLE.get(tok, "?") for tok in morse.split())


# ──────────────────────────────────────────────────────────────────────────────
# XOR
# ──────────────────────────────────────────────────────────────────────────────

def xor_single_byte_brute(data: bytes) -> list[tuple[int, str, float]]:
    """
    Try all single-byte XOR keys. Returns list of (key, plaintext, score)
    sorted by English-language score (highest first).
    """
    def score_english(text: str) -> float:
        freq = "etaoin shrdlu"
        return sum(text.lower().count(c) for c in freq) / max(len(text), 1)

    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        try:
            text = decrypted.decode("utf-8")
        except UnicodeDecodeError:
            text = decrypted.decode("latin-1")
        printable_ratio = sum(c in string.printable for c in text) / max(len(text), 1)
        if printable_ratio > 0.85:
            results.append((key, text, score_english(text)))
    results.sort(key=lambda x: -x[2])
    return results


def xor_multi_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def xor_guess_keylen(data: bytes, max_keylen: int = 40) -> list[int]:
    """Hamming distance method to guess XOR key length."""
    def hamming(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    scores = []
    for keylen in range(2, min(max_keylen + 1, len(data) // 4)):
        chunks = [data[i * keylen:(i + 1) * keylen] for i in range(4)]
        pairs = [(chunks[i], chunks[j]) for i in range(4) for j in range(i + 1, 4)
                 if len(chunks[i]) == keylen and len(chunks[j]) == keylen]
        if not pairs:
            continue
        norm = sum(hamming(a, b) / keylen for a, b in pairs) / len(pairs)
        scores.append((keylen, norm))
    scores.sort(key=lambda x: x[1])
    return [k for k, _ in scores[:5]]


def xor_break_multi(data: bytes, keylen: int) -> bytes:
    """Break multi-byte XOR given a key length."""
    key = bytearray()
    for i in range(keylen):
        block = bytes(data[j] for j in range(i, len(data), keylen))
        hits = xor_single_byte_brute(block)
        if hits:
            key.append(hits[0][0])
    return bytes(key)


# ──────────────────────────────────────────────────────────────────────────────
# RSA attacks
# ──────────────────────────────────────────────────────────────────────────────

def long_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, "big")


def rsa_decrypt(c: int, d: int, n: int) -> str:
    """Standard RSA decryption given private key."""
    m = pow(c, d, n)
    try:
        return long_to_bytes(m).decode("utf-8", errors="replace")
    except Exception:
        return hex(m)


def rsa_small_e(c: int, e: int) -> int | None:
    """
    Small public exponent attack: if m^e < n, ciphertext is just m^e.
    Take the integer eth root.
    """
    # Newton's method integer eth root
    if c == 0:
        return 0
    n = int(round(c ** (1 / e)))
    for candidate in [n - 1, n, n + 1]:
        if candidate >= 0 and pow(candidate, e) == c:
            return candidate
    return None


def rsa_common_factor(n1: int, n2: int) -> tuple[int, int] | None:
    """If two RSA moduli share a prime, recover it via GCD."""
    g = math.gcd(n1, n2)
    if 1 < g < n1:
        return (g, n1 // g)
    return None


def rsa_wiener(e: int, n: int):
    """
    Wiener's attack on RSA with small private exponent.
    Returns d if successful, else None.
    """
    def continued_fraction(num, den):
        cf = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf):
        convs = []
        for i in range(len(cf)):
            if i == 0:
                convs.append((cf[0], 1))
            elif i == 1:
                convs.append((cf[0] * cf[1] + 1, cf[1]))
            else:
                h_prev, k_prev = convs[-1]
                h_prev2, k_prev2 = convs[-2]
                convs.append((cf[i] * h_prev + h_prev2, cf[i] * k_prev + k_prev2))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # check if phi is valid: x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sqrt_disc = int(disc ** 0.5)
        if sqrt_disc * sqrt_disc == disc:
            return d
    return None


def factordb_lookup(n: int) -> tuple[int, int] | None:
    """Query factordb.com to factor n (requires internet)."""
    import urllib.request
    try:
        url = f"http://factordb.com/api?query={n}"
        with urllib.request.urlopen(url, timeout=10) as r:
            import json
            data = json.loads(r.read())
            factors = data.get("factors", [])
            if len(factors) == 2:
                return int(factors[0][0]), int(factors[1][0])
    except Exception:
        pass
    return None


def rsa_full_solve(n: int, e: int, c: int) -> str | None:
    """
    Try all RSA attacks in order. Return plaintext if any succeeds.
    """
    # 1. Small e direct root
    m = rsa_small_e(c, e)
    if m is not None:
        return long_to_bytes(m).decode("utf-8", errors="replace")

    # 2. Wiener's attack
    d = rsa_wiener(e, n)
    if d:
        return rsa_decrypt(c, d, n)

    # 3. FactorDB
    factors = factordb_lookup(n)
    if factors:
        p, q = factors
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            return rsa_decrypt(c, d, n)
        except Exception:
            pass

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Misc
# ──────────────────────────────────────────────────────────────────────────────

def rail_fence_decode(ciphertext: str, rails: int) -> str:
    n = len(ciphertext)
    cycle_len = 2 * (rails - 1)
    indices = sorted(range(n), key=lambda i: rails - 1 - abs(i % cycle_len - (rails - 1)))
    result = [""] * n
    for pos, char in zip(sorted(indices), ciphertext):
        result[pos] = char
    return "".join(result)


def columnar_transpose(ciphertext: str, key: str) -> str:
    order = sorted(range(len(key)), key=lambda i: key[i])
    n_cols = len(key)
    n_rows = math.ceil(len(ciphertext) / n_cols)
    extra = n_rows * n_cols - len(ciphertext)
    cols = []
    idx = 0
    for col in range(n_cols):
        col_len = n_rows - (1 if (n_cols - extra <= col) else 0)
        cols.append(list(ciphertext[idx: idx + col_len]))
        idx += col_len
    grid = [[""] * n_cols for _ in range(n_rows)]
    for col_pos, col_data in zip(order, cols):
        for row, ch in enumerate(col_data):
            grid[row][col_pos] = ch
    return "".join("".join(row) for row in grid)


def bacon_decode(text: str) -> str:
    """Bacon's cipher: A=AAAAA, B=AAAAB ... Z=BBBBB"""
    TABLE = {
        "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D",
        "AABAA": "E", "AABAB": "F", "AABBA": "G", "AABBB": "H",
        "ABAAA": "I", "ABAAB": "J", "ABABA": "K", "ABABB": "L",
        "ABBAA": "M", "ABBAB": "N", "ABBBA": "O", "ABBBB": "P",
        "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
        "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X",
        "BAAAA": "Y", "BBBAB": "Z",
    }
    text = text.upper().replace(" ", "")
    groups = [text[i: i + 5] for i in range(0, len(text), 5)]
    return "".join(TABLE.get(g, "?") for g in groups)


def identify_cipher(ciphertext: str) -> list[str]:
    """
    Heuristic identification of likely cipher type(s).
    Returns list of candidate types.
    """
    candidates = []
    text = ciphertext.strip()

    # Check for base64
    b64_chars = set(string.ascii_letters + string.digits + "+/=")
    if all(c in b64_chars for c in text) and len(text) % 4 == 0 and len(text) > 4:
        candidates.append("base64")

    # Hex
    if all(c in string.hexdigits for c in text.replace(" ", "")) and len(text.replace(" ", "")) % 2 == 0:
        candidates.append("hex")

    # Binary
    if all(c in "01 " for c in text):
        candidates.append("binary")

    # Morse
    if all(c in ".-/ " for c in text):
        candidates.append("morse")

    # Only uppercase letters — could be Caesar/Vigenere
    if text.isupper() and text.isalpha():
        candidates.append("caesar")
        candidates.append("vigenere")

    # Only letters, mixed case
    if text.isalpha():
        candidates.append("caesar")
        candidates.append("substitution")

    # Numbers that could be RSA or decimal
    if text.replace(" ", "").isdigit():
        candidates.append("rsa_ciphertext")
        candidates.append("decimal_list")

    # Default
    if not candidates:
        candidates.append("unknown — try xor or custom encoding")

    return candidates