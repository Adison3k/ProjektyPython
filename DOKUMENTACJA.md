# Dokumentacja Techniczna — Tester Odporności Haseł

**Plik:** `password_tester.py`  
**Wersja:** 1.0  
**Python:** 3.10+  
**Zależności:** brak zewnętrznych (tylko biblioteka standardowa)

---

## Spis treści

1. [Architektura](#1-architektura)
2. [Struktury danych](#2-struktury-danych)
3. [Moduł 1 — Analiza siły hasła](#3-moduł-1--analiza-siły-hasła)
4. [Moduł 2 — Atak słownikowy](#4-moduł-2--atak-słownikowy)
5. [Moduł 3 — Szacowanie brute-force](#5-moduł-3--szacowanie-brute-force)
6. [Moduł 4 — Pełny raport](#6-moduł-4--pełny-raport)
7. [Moduł 5 — Wyświetlanie w terminalu](#7-moduł-5--wyświetlanie-w-terminalu)
8. [Tryby uruchomienia](#8-tryby-uruchomienia)
9. [API publiczne](#9-api-publiczne)
10. [Słownik wbudowany](#10-słownik-wbudowany)
11. [Algorytm scoringu siły](#11-algorytm-scoringu-siły)
12. [Bezpieczeństwo i prywatność](#12-bezpieczeństwo-i-prywatność)

---

## 1. Architektura

Aplikacja jest zbudowana jako pojedynczy plik Python z czytelnym podziałem na sekcje:

```
password_tester.py
│
├── Dane globalne
│   ├── COMMON_PASSWORDS  – wbudowana lista słownikowa
│   └── LEET_MAP          – tablica transliteracji leet-speak
│
├── Struktury danych (dataclasses)
│   ├── StrengthResult    – wynik analizy siły
│   ├── DictionaryResult  – wynik ataku słownikowego
│   ├── BruteForceResult  – wynik szacowania / złamania brute-force
│   └── FullReport        – zagregowany raport końcowy
│
├── Moduł 1: analyze_strength()
├── Moduł 2: dictionary_attack()
├── Moduł 3: brute_force_estimate()
├── Moduł 4: full_report()
├── Moduł 5: print_report() + helpers wizualne
│
└── Punkt wejścia: interactive_mode() / batch_mode()
```

Każdy moduł jest niezależny — można go wywołać osobno lub użyć funkcji `full_report()` jako fasady agregującej wszystkie wyniki.

---

## 2. Struktury danych

### `StrengthResult`

```python
@dataclass
class StrengthResult:
    score: int           # Wynik 0–100
    label: str           # Opisowy poziom siły
    entropy: float       # Entropia w bitach (Shannon)
    charset_size: int    # Liczba unikalnych możliwych znaków
    length: int          # Długość hasła
    issues: list[str]    # Lista wykrytych problemów
    tips: list[str]      # Lista wskazówek poprawy
```

| Pole | Typ | Opis |
|------|-----|------|
| `score` | `int` | Liczba od 0 do 100; odzwierciedla łączną siłę hasła |
| `label` | `str` | Jedna z 5 etykiet: Bardzo słabe, Słabe, Średnie, Silne, Bardzo silne |
| `entropy` | `float` | Bity entropii = `długość × log₂(rozmiar_zestawu)` |
| `charset_size` | `int` | Suma możliwych symboli: 26 (a-z) + 26 (A-Z) + 10 (0-9) + 32 (specjalne) |
| `issues` | `list[str]` | Problemy znalezione w haśle (np. brak cyfr, powtórzenia) |
| `tips` | `list[str]` | Konkretne zalecenia poprawy |

---

### `DictionaryResult`

```python
@dataclass
class DictionaryResult:
    found: bool
    matched_word: Optional[str]   # Słowo ze słownika, które pasowało
    variant_type: Optional[str]   # Typ dopasowania
    time_ms: float                # Czas analizy w milisekundach
```

**Możliwe wartości `variant_type`:**

| Wartość | Opis | Przykład |
|---------|------|---------|
| `"exact"` | Dokładne dopasowanie | `password` → `password` |
| `"leet-speak"` | Po odkodowaniu leet | `p@ssw0rd` → `password` |
| `"reversed"` | Odwrócone hasło | `drowssap` → `password` |
| `"capitalized"` | Z wielką pierwszą literą | `Password` → `password` |

---

### `BruteForceResult`

```python
@dataclass
class BruteForceResult:
    estimated_time_seconds: float   # Szacowany czas łamania w sekundach
    estimated_time_human: str       # Czytelna wersja czasu (np. "16 tys. lat")
    combinations: int               # Liczba możliwych kombinacji = charset^length
    charset_desc: str               # Opis użytego zestawu znaków
    length: int                     # Długość hasła
    cracked_if_short: bool          # True jeśli hasło faktycznie złamano lokalnie
    cracked_password: Optional[str] # Złamane hasło (tylko dla ≤ 5 znaków alfanum)
    crack_time_ms: float            # Rzeczywisty czas złamania w ms
```

---

### `FullReport`

```python
@dataclass
class FullReport:
    password: str
    strength: StrengthResult
    dictionary: DictionaryResult
    brute_force: BruteForceResult
    sha256: str          # Hash SHA-256 hasła (hex, 64 znaki)
    md5: str             # Hash MD5 hasła (hex, 32 znaki)
    overall_verdict: str # Werdykt: "✅ HASŁO BEZPIECZNE" itp.
    overall_color: str   # "red" | "yellow" | "green"
```

---

## 3. Moduł 1 — Analiza siły hasła

### Funkcja: `analyze_strength(password: str) → StrengthResult`

Oblicza siłę hasła na podstawie kilku kryteriów i zwraca wynik w skali 0–100.

#### Schemat działania

```
Wejście: hasło (str)
    │
    ├─ Wykrycie zestawu znaków
    │   ├─ małe litery?  → +26 do charset_size
    │   ├─ wielkie litery? → +26
    │   ├─ cyfry?        → +10
    │   └─ znaki specjalne? → +32
    │
    ├─ Obliczenie entropii: E = len × log₂(charset_size)
    │
    ├─ Punktacja bazowa (od długości):
    │   ├─ < 6 znaków  → 0 pkt + issue
    │   ├─ 6–7 znaków  → 10 pkt
    │   ├─ 8–11 znaków → 25 pkt
    │   ├─ 12–15 znaków → 35 pkt
    │   └─ 16+ znaków  → 45 pkt
    │
    ├─ Premia za różnorodność: +10 pkt za każdą kategorię znaków
    │
    ├─ Kary:
    │   ├─ Powtórzenia (aaa, 111) → -10 pkt
    │   ├─ Sekwencje (123, abc, qwe) → -8 pkt
    │   └─ Popularne hasła (password, admin) → -30 pkt
    │
    └─ Wynik: max(0, min(100, score))
```

#### Etykiety poziomów

| Zakres score | Etykieta |
|-------------|----------|
| 0–19 | Bardzo słabe |
| 20–39 | Słabe |
| 40–59 | Średnie |
| 60–79 | Silne |
| 80–100 | Bardzo silne |

---

## 4. Moduł 2 — Atak słownikowy

### Funkcja: `dictionary_attack(password: str, extra_words: list[str] | None = None) → DictionaryResult`

Sprawdza hasło i jego typowe warianty względem wbudowanego słownika.

#### Schemat działania

```python
for word in wordlist:
    1. Czy password.lower() == word?            → "exact"
    2. Czy leet_decode(password) == word?       → "leet-speak"
    3. Czy password.lower() == word[::-1]?      → "reversed"
    4. Czy password.lower() == word.capitalize()? → "capitalized"
```

#### Funkcja `_leet_decode()`

Transliteruje typowe podstawienia leet-speak używając tabeli:

| Leet | Litera |
|------|--------|
| `4` | a |
| `8` | b |
| `3` | e |
| `1` | I |
| `!` | i |
| `0` | o |
| `@` | a |
| `$` | s |

#### Parametr `extra_words`

Umożliwia przekazanie dodatkowej listy słów (np. z zewnętrznego pliku):

```python
with open("rockyou_top1000.txt") as f:
    extra = [line.strip() for line in f]

result = dictionary_attack("mojeSłowo", extra_words=extra)
```

---

## 5. Moduł 3 — Szacowanie brute-force

### Funkcja: `brute_force_estimate(password: str) → BruteForceResult`

Szacuje czas złamania hasła metodą brute-force oraz (opcjonalnie) faktycznie je łamie dla krótkich haseł.

#### Stała `GPU_SPEED`

```python
GPU_SPEED = 10_000_000_000  # 10 miliardów prób/sekundę
```

Odpowiada przybliżonej szybkości hashcata na GPU klasy consumer (np. RTX 3080) dla algorytmu MD5. Dla bcrypt/Argon2 rzeczywisty czas byłby wielokrotnie dłuższy.

#### Wzór szacowania

```
kombinacje = charset_size ^ długość_hasła
czas_s     = kombinacje / GPU_SPEED
```

#### Faktyczne łamanie brute-force

Dla haseł spełniających warunki:
- długość ≤ 5 znaków
- tylko znaki alfanumeryczne (brak specjalnych)

aplikacja iteruje wszystkie możliwe kombinacje od długości 1 do `len(password)` i mierzy rzeczywisty czas w ms.

```python
for attempt_len in range(1, length + 1):
    for combo in itertools.product(charset, repeat=attempt_len):
        candidate = "".join(combo)
        if candidate == password:
            # znaleziono!
```

#### Funkcja `_human_time()`

Przelicza sekundy na czytelny opis:

| Zakres | Format |
|--------|--------|
| < 1 ms | `X.XX ms` |
| < 1 s | `X.XXX s` |
| < 60 s | `X.X sekund` |
| < 1 h | `X.X minut` |
| < 1 d | `X.X godzin` |
| < 1 rok | `X.X dni` |
| < 1 mln lat | `X.X lat` |
| < 1 mld lat | `X.XX milionów lat` |
| powyżej | notacja naukowa `X.XXe+N lat` |

---

## 6. Moduł 4 — Pełny raport

### Funkcja: `full_report(password: str) → FullReport`

Fasada agregująca wszystkie analizy w jeden obiekt `FullReport`.

#### Logika werdyktu

```python
if dictionary.found or strength.score < 20 or brute_force_time < 1s:
    verdict = "❌ HASŁO NIEBEZPIECZNE"   # kolor: red
elif strength.score < 50 or brute_force_time < 3600s:
    verdict = "⚠️  HASŁO SŁABE"          # kolor: yellow
else:
    verdict = "✅ HASŁO BEZPIECZNE"      # kolor: green
```

Werdykt jest wyznaczany **pesymistycznie** — wystarczy spełnienie jednego z negatywnych warunków.

---

## 7. Moduł 5 — Wyświetlanie w terminalu

### Funkcja: `print_report(r: FullReport) → None`

Wyświetla sformatowany raport z kolorami ANSI.

#### Kolory ANSI

| Kolor | Kod | Zastosowanie |
|-------|-----|-------------|
| `red` | `\033[91m` | Niebezpieczne, błędy |
| `yellow` | `\033[93m` | Ostrzeżenia |
| `green` | `\033[92m` | Bezpieczne, OK |
| `cyan` | `\033[96m` | Ramki, nagłówki |
| `bold` | `\033[1m` | Tytuły sekcji |

#### Maskowanie hasła

Hasło w raporcie jest maskowane: pierwsze 3 znaki są widoczne, reszta zastąpiona gwiazdkami.

```python
masked = password[:3] + "*" * max(0, len(password) - 3)
# "password123" → "pas********"
```

#### Pasek postępu

```python
def bar(score: int, width: int = 40) -> str:
    filled = int(score / 100 * width)
    color  = "red" if score < 40 else ("yellow" if score < 70 else "green")
    return c("█" * filled, color) + "░" * (width - filled) + f"  {score}/100"
```

---

## 8. Tryby uruchomienia

### Tryb interaktywny

```bash
python3 password_tester.py
```

Pętla `while True` czyta hasła z `stdin`. Obsługuje `KeyboardInterrupt` (Ctrl+C) i `EOFError`. Hasła `quit`, `exit`, `q` kończą program.

### Tryb wsadowy

```bash
python3 password_tester.py haslo1 haslo2 haslo3
```

Wywołuje `batch_mode(sys.argv[1:])`, która przetwarza listę haseł i zwraca `list[FullReport]`.

---

## 9. API publiczne

Wszystkie poniższe funkcje i klasy są eksportowalne jako moduł:

```python
from password_tester import (
    analyze_strength,      # (str) → StrengthResult
    dictionary_attack,     # (str, extra_words?) → DictionaryResult
    brute_force_estimate,  # (str) → BruteForceResult
    full_report,           # (str) → FullReport
    print_report,          # (FullReport) → None
    batch_mode,            # (list[str]) → list[FullReport]
    StrengthResult,
    DictionaryResult,
    BruteForceResult,
    FullReport,
)
```

#### Przykład integracji

```python
from password_tester import full_report

passwords = ["test123", "Qk7#mN!2pL"]
for pw in passwords:
    r = full_report(pw)
    status = "OK" if r.overall_color == "green" else "SŁABE"
    print(f"{pw[:4]}*** → {status} (score: {r.strength.score}, entropia: {r.strength.entropy} bit)")
```

#### Przykład z własnym słownikiem

```python
from password_tester import dictionary_attack

with open("slownik.txt", encoding="utf-8") as f:
    slownik = [line.strip().lower() for line in f if line.strip()]

result = dictionary_attack("SuperTajne", extra_words=slownik)
if result.found:
    print(f"Znaleziono! Typ: {result.variant_type}, słowo: {result.matched_word}")
```

---

## 10. Słownik wbudowany

Stała `COMMON_PASSWORDS` zawiera ~60 haseł podzielonych tematycznie:

| Kategoria | Przykłady |
|-----------|-----------|
| Najpopularniejsze globalne | `password`, `123456`, `qwerty`, `admin` |
| Słowa angielskie | `monkey`, `dragon`, `sunshine`, `letmein` |
| Popkultura | `batman`, `starwars`, `superman` |
| Polskie | `polska`, `haslo`, `haslo123` |
| Wzory numeryczne | `111111`, `123123`, `000000` |
| Wzory klawiaturowe | `qazwsx`, `zaq12wsx` |

---

## 11. Algorytm scoringu siły

Pełna tabela punktacji:

| Kryterium | Punkty |
|-----------|--------|
| Długość < 6 | 0 + issue |
| Długość 6–7 | +10 |
| Długość 8–11 | +25 |
| Długość 12–15 | +35 |
| Długość 16+ | +45 |
| Zawiera małe litery | +10 |
| Zawiera wielkie litery | +10 |
| Zawiera cyfry | +10 |
| Zawiera znaki specjalne | +10 |
| Powtórzenia (aaa, 111) | -10 |
| Sekwencje (123, abc, qwe) | -8 |
| Popularne hasło (password, admin) | -30 |

Wynik jest ograniczony do przedziału [0, 100].

---

## 12. Bezpieczeństwo i prywatność

- **Brak połączeń sieciowych** — aplikacja nie wysyła żadnych danych. Wszystkie operacje są lokalne.
- **Hasło w pamięci** — hasło istnieje wyłącznie w pamięci procesu Python podczas działania programu.
- **Maskowanie w raporcie** — w wydruku widoczne są tylko pierwsze 3 znaki hasła.
- **Hashe wyłącznie edukacyjnie** — SHA-256 i MD5 są obliczane lokalnie i służą jedynie do demonstracji; aplikacja nie przechowuje ich ani nie porównuje z bazami.
- **MD5 jest przestarzały** — wyświetlany wyłącznie jako przykład słabego algorytmu; nie należy go używać do przechowywania haseł.

> **Uwaga:** Aplikacja jest narzędziem edukacyjnym. Szacowanie brute-force zakłada atak GPU na zahashowane hasło (MD5) — rzeczywisty czas dla bezpiecznych algorytmów (bcrypt, Argon2) jest wielokrotnie dłuższy. Nie używaj aplikacji do testowania cudzych haseł bez zgody właściciela.
