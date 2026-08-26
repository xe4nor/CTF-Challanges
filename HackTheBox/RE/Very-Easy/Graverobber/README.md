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

In dieser Challenge besteht das Ziel darin, die bereitgestellte Binary zu analysieren 
und herauszufinden, welche Eingabe benötigt wird, um den erfolgreichen Programmpfad zu erreichen.

Dabei möchte ich nicht einfach die richtige Eingabe
erraten oder bruteforcen, sondern nachvollziehen, wie das Programm die Eingabe verarbeitet und überprüft.

---

# 1. Erste Analyse der Binary

Bevor ich die Datei in Ghidra öffne, sammle ich zunächst grundlegende Informationen.

```bash
file robber
```

## Ausgabe

```text
robber: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)
```

## Erkenntnisse

* Es handelt sich um eine Linux Binary
* 64-Bit
* PIE ist aktiviert

## Offene Fragen

* wo wird die Benutzereingabe eingelesen ?
* Wo wird die Eingabe überprüft ?
* Welche Eingabe führt zu der HTB{...} Flag ? 

---

# 2. Strings untersuchen

Als Nächstes suche ich nach lesbaren Strings innerhalb der Binary.

```bash
strings robber
```

## Interessante Strings

```text
We took a wrong turning!
We found the treasure! (I hope it's not cursed)
```

## Beobachtungen

---

# 3. Programmverhalten untersuchen

Bevor ich mit der tieferen statischen Analyse beginne, führe ich die Binary aus.

```bash
sudo chmod +x robber
```

## Eingabe

```text
1234
asdf
```

## Ausgabe

```text
beides hat das Programm beendet
```

## Beobachtungen

Als man das Programm gestartet hat, hat es nicht nach einer Benutzereingabe gefragt. Daraufhin habe ich probiert das Programm mit Argumenten zu starten sowohl zahlen als auch Buchstaben.
Beides hat das Programm sofort beendet.

<img width="940" height="328" alt="image" src="https://github.com/user-attachments/assets/7bb95c18-2d09-49bf-b390-30a094f8bd8c" />

---

# 4. Analyse mit Ghidra

## `main()`

```c
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  uint local_ec;
  stat local_e8;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_58[0] = '\0';
  local_58[1] = '\0';
  local_58[2] = '\0';
  local_58[3] = '\0';
  local_58[4] = '\0';
  local_58[5] = '\0';
  local_58[6] = '\0';
  local_58[7] = '\0';
  local_58[8] = '\0';
  local_58[9] = '\0';
  local_58[10] = '\0';
  local_58[0xb] = '\0';
  local_58[0xc] = '\0';
  local_58[0xd] = '\0';
  local_58[0xe] = '\0';
  local_58[0xf] = '\0';
  local_58[0x10] = '\0';
  local_58[0x11] = '\0';
  local_58[0x12] = '\0';
  local_58[0x13] = '\0';
  local_58[0x14] = '\0';
  local_58[0x15] = '\0';
  local_58[0x16] = '\0';
  local_58[0x17] = '\0';
  local_58[0x18] = '\0';
  local_58[0x19] = '\0';
  local_58[0x1a] = '\0';
  local_58[0x1b] = '\0';
  local_58[0x1c] = '\0';
  local_58[0x1d] = '\0';
  local_58[0x1e] = '\0';
  local_58[0x1f] = '\0';
  local_58[0x20] = '\0';
  local_58[0x21] = '\0';
  local_58[0x22] = '\0';
  local_58[0x23] = '\0';
  local_58[0x24] = '\0';
  local_58[0x25] = '\0';
  local_58[0x26] = '\0';
  local_58[0x27] = '\0';
  local_58[0x28] = '\0';
  local_58[0x29] = '\0';
  local_58[0x2a] = '\0';
  local_58[0x2b] = '\0';
  local_58[0x2c] = '\0';
  local_58[0x2d] = '\0';
  local_58[0x2e] = '\0';
  local_58[0x2f] = '\0';
  local_58[0x30] = '\0';
  local_58[0x31] = '\0';
  local_58[0x32] = '\0';
  local_58[0x33] = '\0';
  local_58[0x34] = '\0';
  local_58[0x35] = '\0';
  local_58[0x36] = '\0';
  local_58[0x37] = '\0';
  local_58[0x38] = '\0';
  local_58[0x39] = '\0';
  local_58[0x3a] = '\0';
  local_58[0x3b] = '\0';
  local_58[0x3c] = '\0';
  local_58[0x3d] = '\0';
  local_58[0x3e] = '\0';
  local_58[0x3f] = '\0';
  local_58[0x40] = '\0';
  local_58[0x41] = '\0';
  local_58[0x42] = '\0';
  local_58[0x43] = '\0';
  local_ec = 0;
  do {
    if (0x1f < local_ec) {
      puts("We found the treasure! (I hope it\'s not cursed)");
      uVar2 = 0;
LAB_00101256:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar2;
    }
    local_58[(int)(local_ec * 2)] = (char)*(undefined4 *)(parts + (long)(int)local_ec * 4);
    local_58[(int)(local_ec * 2 + 1)] = '/';
    iVar1 = stat(local_58,&local_e8);
    if (iVar1 != 0) {
      puts("We took a wrong turning!");
      uVar2 = 1;
      goto LAB_00101256;
    }
    local_ec = local_ec + 1;
  } while( true );
}

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
