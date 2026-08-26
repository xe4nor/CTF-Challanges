# HTB Reverse Engineering – `Graverobber`

> **Plattform:** HackTheBox

> **Kategorie:** Reverse Engineering

> **Schwierigkeit:** Very-Easy

> **Architektur:** x68-64
> **Dateityp:** ELF 64-bit
> **Tools:** Ghidra, strings, file
> **Status:** Unsolved (running)

---

# Übersicht

---

# 1. Erste Analyse der Binary

```bash
```

## Ausgabe

```text
```

## Erkenntnisse

*
*
*

## Offene Fragen

*
*
*

---

# 2. Strings untersuchen

```bash
```

## Interessante Strings

```text
```

## Beobachtungen

---

# 3. Programmverhalten untersuchen

```bash
```

## Eingabe

```text
```

## Ausgabe

```text
```

## Beobachtungen

---

# 4. Analyse mit Ghidra

## `main()`

```c
```

## Beobachtungen

## Interessante Funktionen

*
*
*

---

# 5. Datenfluss / Benutzereingabe verfolgen

```text
```

## Erkenntnisse

*
*
*

## Offene Fragen

*
*
*

---

# 6. Analyse der relevanten Funktion

## Funktion

```text
```

## Decompiler

```c
```

## Beobachtungen

---

# 7. Algorithmus / Validierungslogik

## Erkannte Operationen

```text
```

## Analyse

```text
```

## Berechnungen

```text
```

## Erkenntnisse

---

# 8. Eingabe / Lösung rekonstruieren

## Wert 1

```text
```

## Wert 2

```text
```

## Wert 3

```text
```

## Weitere Werte

```text
```

## Rekonstruiertes Ergebnis

```text
```

---

# 9. Assembly-Analyse

```asm
```

## Relevante Instruktionen

### `<Instruktion>`

### `<Instruktion>`

### `<Instruktion>`

## Erkenntnisse

---

# 10. Solver

## `solve.c`

```c
```

## Kompilieren

```bash
```

## Ausführen

```bash
```

## Ausgabe

```text
```

---

# 11. Lösung verifizieren

## Ausführen

```bash
```

## Eingabe

```text
```

## Ausgabe

```text
```

## Ergebnis

---

#  Was habe ich gelernt?

## Technische Erkenntnisse

*
*
*

## Neue Instruktionen / Funktionen

*
*
*

## Neue Reverse-Engineering-Techniken

*
*
*

---

#  Was war während der Analyse unklar?

## Problem / Frage 1

### Erklärung

---

## Problem / Frage 2

### Erklärung

---

## Problem / Frage 3

### Erklärung

---

#  Sackgassen / Fehlversuche

## Versuch 1

### Warum hat es nicht funktioniert?

### Was habe ich daraus gelernt?

---

## Versuch 2

### Warum hat es nicht funktioniert?

### Was habe ich daraus gelernt?

---

#  Notizen

```text
```

---

#  Zusammenfassung des Analysewegs

```text
Binary
   │
   ▼

   │
   ▼

   │
   ▼

   │
   ▼

   │
   ▼

```

---

#  Fazit

---

#  Screenshots

## Screenshot 1

```text
```

### Beschreibung

---

## Screenshot 2

```text
```

### Beschreibung

---

## Screenshot 3

```text
```

### Beschreibung

---

#  Dateien

```text
<Challenge-Name>/
│
├── README.md
├── 
└── 
```

---

## Hinweis

Ich veröffentliche nur Inhalte, deren Veröffentlichung durch die jeweilige Plattform erlaubt ist. Challenge-Binaries, Flags oder andere geschützte Dateien werden nicht ohne entsprechende Erlaubnis in das Repository aufgenommen.
