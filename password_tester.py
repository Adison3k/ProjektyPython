#!/usr/bin/env python3
"""
Aplikacja do testowania odporności haseł
Testuje hasła pod kątem: siły, ataków słownikowych i brute-force
"""

import re
import time
import math
import hashlib
import itertools
import string
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
#  Dane słownikowe (wbudowane, bez zewnętrznych plików)
# ─────────────────────────────────────────────

COMMON_PASSWORDS = [
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "letmein", "monkey", "dragon", "master", "sunshine",
    "princess", "welcome", "shadow", "superman", "iloveyou", "admin",
    "login", "pass", "test", "guest", "root", "toor", "changeme",
    "secret", "passwd", "football", "baseball", "soccer", "hockey",
    "batman", "starwars", "trustno1", "zaq12wsx", "qazwsx", "qwerty123",
    "polska", "haslo", "haslo123", "admin123", "user", "user123",
    "pass123", "password123", "1234", "12345", "1234567", "12345678",
    "123123", "111222", "000000", "696969", "007007",
]

LEET_MAP = str.maketrans("4831!0@$", "abeIioas")


# ─────────────────────────────────────────────
#  Struktury wyników
# ─────────────────────────────────────────────

@dataclass
class StrengthResult:
    score: int           # 0–100
    label: str           # Bardzo słabe / Słabe / Średnie / Silne / Bardzo silne
    entropy: float       # bity entropii
    charset_size: int
    length: int
    issues: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)

@dataclass
class DictionaryResult:
    found: bool
    matched_word: Optional[str] = None
    variant_type: Optional[str] = None   # "exact" | "leet" | "capitalized" | "reversed"
    time_ms: float = 0.0

@dataclass
class BruteForceResult:
    estimated_time_seconds: float
    estimated_time_human: str
    combinations: int
    charset_desc: str
    length: int
    cracked_if_short: bool = False
    cracked_password: Optional[str] = None
    crack_time_ms: float = 0.0

@dataclass
class FullReport:
    password: str
    strength: StrengthResult
    dictionary: DictionaryResult
    brute_force: BruteForceResult
    sha256: str
    md5: str
    overall_verdict: str
    overall_color: str   # red / yellow / green


# ─────────────────────────────────────────────
#  1. Analiza siły hasła
# ─────────────────────────────────────────────

def analyze_strength(password: str) -> StrengthResult:
    length = len(password)
    issues = []
    tips = []

    # Rozmiar zestawu znaków
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    charset_size = 0
    if has_lower:   charset_size += 26
    if has_upper:   charset_size += 26
    if has_digit:   charset_size += 10
    if has_special: charset_size += 32

    charset_size = max(charset_size, 1)

    # Entropia Shannona
    entropy = length * math.log2(charset_size) if charset_size > 1 else 0

    # Punktacja bazowa
    score = 0

    # Długość
    if length < 6:
        issues.append("Hasło jest za krótkie (min. 8 znaków)")
        tips.append("Użyj co najmniej 8 znaków, najlepiej 12+")
    elif length < 8:
        score += 10
        tips.append("Zwiększ długość do przynajmniej 12 znaków")
    elif length < 12:
        score += 25
    elif length < 16:
        score += 35
    else:
        score += 45

    # Różnorodność znaków
    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 10

    if not has_lower:
        issues.append("Brak małych liter")
        tips.append("Dodaj małe litery (a–z)")
    if not has_upper:
        issues.append("Brak wielkich liter")
        tips.append("Dodaj wielkie litery (A–Z)")
    if not has_digit:
        issues.append("Brak cyfr")
        tips.append("Dodaj cyfry (0–9)")
    if not has_special:
        tips.append("Dodaj znaki specjalne (!@#$%^&*) dla większej siły")

    # Kary
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("Powtarzające się znaki (np. 'aaa')")

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|wer|ert)', password.lower()):
        score -= 8
        issues.append("Sekwencja klawiaturowa lub numeryczna")

    if password.lower() in ('password', 'haslo', 'qwerty', 'admin'):
        score -= 30
        issues.append("Hasło jest jednym z najczęściej używanych!")

    score = max(0, min(100, score))

    # Etykieta
    if score < 20:
        label = "Bardzo słabe"
    elif score < 40:
        label = "Słabe"
    elif score < 60:
        label = "Średnie"
    elif score < 80:
        label = "Silne"
    else:
        label = "Bardzo silne"

    return StrengthResult(
        score=score,
        label=label,
        entropy=round(entropy, 2),
        charset_size=charset_size,
        length=length,
        issues=issues,
        tips=tips,
    )


# ─────────────────────────────────────────────
#  2. Atak słownikowy
# ─────────────────────────────────────────────

def _leet_decode(word: str) -> str:
    return word.translate(LEET_MAP)

def dictionary_attack(password: str, extra_words: list[str] | None = None) -> DictionaryResult:
    wordlist = COMMON_PASSWORDS + (extra_words or [])
    start = time.perf_counter()
    pw_lower = password.lower()

    for word in wordlist:
        # Dokładne dopasowanie
        if pw_lower == word:
            elapsed = (time.perf_counter() - start) * 1000
            return DictionaryResult(found=True, matched_word=word, variant_type="exact", time_ms=round(elapsed, 3))

        # Leet-speak
        if _leet_decode(pw_lower) == word:
            elapsed = (time.perf_counter() - start) * 1000
            return DictionaryResult(found=True, matched_word=word, variant_type="leet-speak", time_ms=round(elapsed, 3))

        # Odwrócone
        if pw_lower == word[::-1]:
            elapsed = (time.perf_counter() - start) * 1000
            return DictionaryResult(found=True, matched_word=word, variant_type="reversed", time_ms=round(elapsed, 3))

        # Z wielką literą
        if pw_lower == word.capitalize():
            elapsed = (time.perf_counter() - start) * 1000
            return DictionaryResult(found=True, matched_word=word, variant_type="capitalized", time_ms=round(elapsed, 3))

    elapsed = (time.perf_counter() - start) * 1000
    return DictionaryResult(found=False, time_ms=round(elapsed, 3))


# ─────────────────────────────────────────────
#  3. Szacowanie czasu brute-force + próba złamania (krótkie hasła)
# ─────────────────────────────────────────────

# Przyjmujemy ~10 miliardów prób/s (GPU klasy consumer)
GPU_SPEED = 10_000_000_000

def _human_time(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1000:.2f} ms"
    if seconds < 1:
        return f"{seconds:.3f} s"
    if seconds < 60:
        return f"{seconds:.1f} sekund"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minut"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} godzin"
    if seconds < 365.25 * 86400:
        return f"{seconds / 86400:.1f} dni"
    years = seconds / (365.25 * 86400)
    if years < 1e6:
        return f"{years:.1f} lat"
    if years < 1e9:
        return f"{years / 1e6:.2f} milionów lat"
    return f"{years:.2e} lat"

def _detect_charset(password: str) -> tuple[str, int]:
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    chars = ""
    desc_parts = []
    if has_lower:   chars += string.ascii_lowercase; desc_parts.append("a-z")
    if has_upper:   chars += string.ascii_uppercase; desc_parts.append("A-Z")
    if has_digit:   chars += string.digits;          desc_parts.append("0-9")
    if has_special: chars += string.punctuation;     desc_parts.append("znaki specjalne")

    if not chars:
        chars = string.ascii_lowercase
        desc_parts = ["a-z"]

    return ", ".join(desc_parts), len(set(chars))

def brute_force_estimate(password: str) -> BruteForceResult:
    length = len(password)
    charset_desc, charset_size = _detect_charset(password)
    combinations = charset_size ** length
    estimated_seconds = combinations / GPU_SPEED

    cracked = False
    cracked_pw = None
    crack_ms = 0.0

    # Faktyczna próba złamania dla bardzo krótkich haseł (≤ 5 znaków, tylko alfanum)
    if length <= 5 and not re.search(r'[^a-zA-Z0-9]', password):
        charset = ""
        if re.search(r'[a-z]', password): charset += string.ascii_lowercase
        if re.search(r'[A-Z]', password): charset += string.ascii_uppercase
        if re.search(r'\d', password):    charset += string.digits
        if not charset: charset = string.ascii_lowercase + string.digits

        start = time.perf_counter()
        for attempt_len in range(1, length + 1):
            for combo in itertools.product(charset, repeat=attempt_len):
                candidate = "".join(combo)
                if candidate == password:
                    cracked = True
                    cracked_pw = candidate
                    break
            if cracked:
                break
        crack_ms = round((time.perf_counter() - start) * 1000, 3)

    return BruteForceResult(
        estimated_time_seconds=estimated_seconds,
        estimated_time_human=_human_time(estimated_seconds),
        combinations=combinations,
        charset_desc=charset_desc,
        length=length,
        cracked_if_short=cracked,
        cracked_password=cracked_pw,
        crack_time_ms=crack_ms,
    )


# ─────────────────────────────────────────────
#  4. Pełny raport
# ─────────────────────────────────────────────

def full_report(password: str) -> FullReport:
    strength  = analyze_strength(password)
    dictionary = dictionary_attack(password)
    bf        = brute_force_estimate(password)
    sha256    = hashlib.sha256(password.encode()).hexdigest()
    md5       = hashlib.md5(password.encode()).hexdigest()

    # Werdykt
    if dictionary.found or strength.score < 20 or bf.estimated_time_seconds < 1:
        verdict = "HASŁO NIEBEZPIECZNE"
        color = "red"
    elif strength.score < 50 or bf.estimated_time_seconds < 3600:
        verdict = "HASŁO SŁABE"
        color = "yellow"
    else:
        verdict = "HASŁO BEZPIECZNE"
        color = "green"

    return FullReport(
        password=password,
        strength=strength,
        dictionary=dictionary,
        brute_force=bf,
        sha256=sha256,
        md5=md5,
        overall_verdict=verdict,
        overall_color=color,
    )


# ─────────────────────────────────────────────
#  5. Wyświetlanie raportu w terminalu
# ─────────────────────────────────────────────

COLORS = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def bar(score: int, width: int = 40) -> str:
    filled = int(score / 100 * width)
    color = "red" if score < 40 else ("yellow" if score < 70 else "green")
    return c("█" * filled, color) + "░" * (width - filled) + f"  {score}/100"

def print_report(r: FullReport) -> None:
    W = 60
    print()
    print(c("═" * W, "cyan"))
    print(c("  RAPORT BEZPIECZEŃSTWA HASŁA", "bold"))
    print(c("═" * W, "cyan"))

    # Maskuj hasło po 3 znakach
    masked = r.password[:3] + "*" * max(0, len(r.password) - 3)
    print(f"\n  Hasło        : {masked}")
    print(f"  Długość      : {r.strength.length} znaków")
    print(f"  Zestaw znaków: {r.strength.charset_size} możliwych symboli")
    print(f"  Entropia     : {r.strength.entropy} bitów")

    print(f"\n  {c('[ SIŁA HASŁA ]', 'bold')}")
    print(f"  {bar(r.strength.score)}")
    print(f"  Ocena: {c(r.strength.label, r.overall_color)}")

    if r.strength.issues:
        print(f"\n  {c('Problemy:', 'yellow')}")
        for issue in r.strength.issues:
            print(f"    • {issue}")

    if r.strength.tips:
        print(f"\n  {c('Wskazówki:', 'cyan')}")
        for tip in r.strength.tips:
            print(f"    → {tip}")

    print(f"\n  {c('[ ATAK SŁOWNIKOWY ]', 'bold')}")
    if r.dictionary.found:
        print(f"  {c('✗ ZNALEZIONO w słowniku!', 'red')}")
        print(f"    Dopasowanie: '{r.dictionary.matched_word}'  (typ: {r.dictionary.variant_type})")
    else:
        print(f"  {c('✓ Nie znaleziono w słowniku', 'green')}")
    print(f"  Czas analizy: {r.dictionary.time_ms} ms")

    print(f"\n  {c('[ ATAK BRUTE-FORCE (GPU ~10 mld prób/s) ]', 'bold')}")
    print(f"  Możliwych kombinacji : {r.brute_force.combinations:,}")
    print(f"  Użyty zestaw znaków  : {r.brute_force.charset_desc}")
    est_color = "green" if r.brute_force.estimated_time_seconds > 86400 else (
                "yellow" if r.brute_force.estimated_time_seconds > 60 else "red")
    print(f"  Szacowany czas łamania: {c(r.brute_force.estimated_time_human, est_color)}")

    if r.brute_force.cracked_if_short:
        print(f"  {c('✗ HASŁO ZŁAMANE LOKALNIE!', 'red')} (czas: {r.brute_force.crack_time_ms} ms)")
    elif r.brute_force.length <= 5:
        print(f"  {c('⚠ Hasło bardzo krótkie — natychmiast do złamania', 'red')}")

    print(f"\n  {c('[ HASHE ]', 'bold')}")
    print(f"  SHA-256 : {r.sha256[:32]}…")
    print(f"  MD5     : {r.md5}")

    print(f"\n  {c('═' * (W - 2), 'cyan')}")
    print(f"  Werdykt: {c(r.overall_verdict, r.overall_color)}")
    print(c("═" * W, "cyan"))
    print()


# ─────────────────────────────────────────────
#  6. Tryb interaktywny
# ─────────────────────────────────────────────

def interactive_mode() -> None:
    print(c("\n╔══════════════════════════════════════════╗", "cyan"))
    print(c("║   Tester odporności haseł  v1.0          ║", "cyan"))
    print(c("║   Wpisz 'quit' aby zakończyć             ║", "cyan"))
    print(c("╚══════════════════════════════════════════╝", "cyan"))

    while True:
        try:
            password = input("\n  Podaj hasło do analizy: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Do widzenia!")
            break

        if password.lower() in ("quit", "exit", "q"):
            print("  Do widzenia!")
            break

        if not password:
            print("  Hasło nie może być puste.")
            continue

        report = full_report(password)
        print_report(report)


# ─────────────────────────────────────────────
#  7. Tryb wsadowy (lista haseł)
# ─────────────────────────────────────────────

def batch_mode(passwords: list[str]) -> list[FullReport]:
    reports = []
    for pw in passwords:
        r = full_report(pw)
        print_report(r)
        reports.append(r)
    return reports


# ─────────────────────────────────────────────
#  Punkt wejścia
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Podano hasła jako argumenty wiersza poleceń
        batch_mode(sys.argv[1:])
    else:
        interactive_mode()
