#  Tester Odporności Haseł

Narzędzie wiersza poleceń do analizy bezpieczeństwa haseł. Testuje hasło pod kątem siły, podatności na atak słownikowy i brute-force — bez zewnętrznych bibliotek, bez wysyłania danych do sieci.

---

## Funkcje

- **Analiza siły** — wynik 0–100 z poziomami: Bardzo słabe / Słabe / Średnie / Silne / Bardzo silne
- **Entropia Shannona** — obliczana na podstawie długości i rozmiaru zestawu znaków
- **Atak słownikowy** — sprawdzanie hasła i jego wariantów (leet-speak, odwrócone, z wielką literą) względem bazy ~60 najpopularniejszych haseł
- **Symulacja brute-force** — szacowanie czasu złamania zakładając GPU ~10 mld prób/s; faktyczne łamanie dla haseł ≤ 5 znaków
- **Hashe** — SHA-256 i MD5 generowane lokalnie (cel edukacyjny)
- **Kolorowy raport** — wynik z paskiem postępu i werdyktem bezpieczeństwa

---

## Wymagania

- Python 3.10 lub nowszy
- Brak zewnętrznych bibliotek (tylko biblioteka standardowa)

---

## Instalacja

```bash
 pobierz plik `password_tester.py`.

---

## Użycie

### Tryb interaktywny

```bash
python3 password_tester.py
```

Program poprosi o wpisanie hasła i wyświetli raport. Wpisz `quit` lub `q` żeby wyjść.

### Tryb wsadowy

```bash
python3 password_tester.py "haslo1" "haslo2" "haslo3"
```

Każde hasło z listy argumentów zostanie przeanalizowane po kolei.

---

## Przykładowy raport

```
════════════════════════════════════════════════════════════
  RAPORT BEZPIECZEŃSTWA HASŁA
════════════════════════════════════════════════════════════

  Hasło        : Tr0********
  Długość      : 11 znaków
  Zestaw znaków: 94 możliwych symboli
  Entropia     : 72.1 bitów

  [ SIŁA HASŁA ]
  ██████████████████████████░░░░░░░░░░░░░░  65/100
  Ocena: Silne

  [ ATAK SŁOWNIKOWY ]
  ✓ Nie znaleziono w słowniku
  Czas analizy: 0.045 ms

  [ ATAK BRUTE-FORCE (GPU ~10 mld prób/s) ]
  Możliwych kombinacji : 5,062,982,072,492,057,196,544
  Użyty zestaw znaków  : a-z, A-Z, 0-9, znaki specjalne
  Szacowany czas łamania: 16043.6 lat

  [ HASHE ]
  SHA-256 : 48486e1514e842346ff405b1e45f4405…
  MD5     : 4ece57a61323b52ccffdbef021956754

  ══════════════════════════════════════════════════════════
  Werdykt:  HASŁO BEZPIECZNE
════════════════════════════════════════════════════════════
```

---

## Użycie jako moduł Python

```python
from password_tester import full_report, print_report

report = full_report("MojeHaslo123!")
print_report(report)

# Dostęp do konkretnych wyników
print(report.strength.score)          # np. 75
print(report.strength.entropy)        # np. 85.4
print(report.dictionary.found)        # True/False
print(report.brute_force.estimated_time_human)  # np. "1200.3 lat"
print(report.overall_verdict)         # " HASŁO BEZPIECZNE"
```

---

## Struktura projektu

```
password-tester/
├── password_tester.py   # Główny plik aplikacji
├── README.md            # Ten plik
└── DOKUMENTACJA.md      # Pełna dokumentacja techniczna
```

---

## Ograniczenia i uwagi

- Słownik jest wbudowany (~60 haseł). Aby testować na większej liście, użyj parametru `extra_words` w funkcji `dictionary_attack()`.
- Szacowanie brute-force zakłada atak na zahashowane hasło z GPU; czas dla logowania sieciowego jest wielokrotnie dłuższy.
- Aplikacja **nie wysyła żadnych danych przez sieć** — wszystkie obliczenia są lokalne.
- Hasło jest maskowane w raporcie (widoczne tylko pierwsze 3 znaki).

---

## Licencja

MIT — do dowolnego użytku, w tym edukacyjnego.

Wykonany projetk w ramach zaliczenia : Adrian Trzciński IS 2 rok
