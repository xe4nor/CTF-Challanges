# HTB Reverse Engineering – `Graverobber`

> **Plattform:** HackTheBox

> **Kategorie:** Reverse Engineering

> **Schwierigkeit:** Very-Easy

> **Architektur:** x68-64

> **Dateityp:** ELF 64-bit

> **Tools:** Ghidra, strings, file

> **Status:** Solved

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

* Der parts Datenbereich liest immer 4 bytes aus (wegen undefined4) und holt sich immer wieder werte aus parts heraus

```c
local_58[(int)(local_ec * 2)] = (char)*(undefined4 *)(parts + (long)(int)local_ec * 4);
```  

---

# 5. Datenfluss / Benutzereingabe verfolgen

```text
Die Schliefe holt sich immer 4 bytes aus dem Datenbereich parts heraus
```

## Erkenntnisse

* Es kann rekonstruiert werden.

---

# 6. Analyse der relevanten Funktion

## Datentyp

```text
parts:

wenn man sich jetzt die den parts Datenbereich genauer anschaut dann sieht man die rohen bytes:

48 00 00 00
54 00 00 00
42 00 00 00

```

## ASM

```asm
                             parts                                           XREF[3]:     Entry Point (*) , 
                                                                                          main:001011d6 (*) , 
                                                                                          main:001011dd (*)   
        00104040 48  00  00       undefine
                 00  54  00 
                 00  00  42 
           

```

# 7. Eingabe / Lösung rekonstruieren

Um die Zeichen zu Rekonstruieren nehmen wir uns die Rohen Bytes und schreiben sie in Hex um und Anschließend bekommen wir einzelnd die ASCII Zeichen 

## Wert 1

```text
48 00 00 00:
0x48 = H (Dezimal 72)
```

## Wert 2

```text
54 00 00 00:
0x54 = T (Dezimal 84)
```

## Wert 3

```text
42 00 00 00:
0x42 = B (Dezimal 66)
```

## Weitere Werte

Genau das selbe machen wir jetzt mit den restlichen roh Bytes:

```asm
                             parts                                           XREF[3]:     Entry Point (*) , 
                                                                                          main:001011d6 (*) , 
                                                                                          main:001011dd (*)   
        00104040 48  00  00       undefine
                 00  54  00 
                 00  00  42 
           00104040 48              undefine  48h                     [0]                               XREF[3]:     Entry Point (*) , 
                                                                                                                     main:001011d6 (*) , 
                                                                                                                     main:001011dd (*)   
           00104041 00              undefine  00h                     [1]
           00104042 00              undefine  00h                     [2]
           00104043 00              undefine  00h                     [3]
           00104044 54              undefine  54h                     [4]
           00104045 00              undefine  00h                     [5]
           00104046 00              undefine  00h                     [6]
           00104047 00              undefine  00h                     [7]
           00104048 42              undefine  42h                     [8]
           00104049 00              undefine  00h                     [9]
           0010404a 00              undefine  00h                     [10]
           0010404b 00              undefine  00h                     [11]


           0010404c 7b              undefine  7Bh                     [12]
           0010404d 00              undefine  00h                     [13]
           0010404e 00              undefine  00h                     [14]
           0010404f 00              undefine  00h                     [15]

           00104050 62              undefine  62h                     [16]
           00104051 00              undefine  00h                     [17]
           00104052 00              undefine  00h                     [18]
           00104053 00              undefine  00h                     [19]

           00104054 72              undefine  72h                     [20]
           00104055 00              undefine  00h                     [21]
           00104056 00              undefine  00h                     [22]
           00104057 00              undefine  00h                     [23]

           00104058 33              undefine  33h                     [24]
           00104059 00              undefine  00h                     [25]
           0010405a 00              undefine  00h                     [26]
           0010405b 00              undefine  00h                     [27]

           0010405c 34              undefine  34h                     [28]
           0010405d 00              undefine  00h                     [29]
           0010405e 00              undefine  00h                     [30]
           0010405f 00              undefine  00h                     [31]

           00104060 6b              undefine  6Bh                     [32]
           00104061 00              undefine  00h                     [33]
           00104062 00              undefine  00h                     [34]
           00104063 00              undefine  00h                     [35]

           00104064 31              undefine  31h                     [36]
           00104065 00              undefine  00h                     [37]
           00104066 00              undefine  00h                     [38]
           00104067 00              undefine  00h                     [39]

           00104068 6e              undefine  6Eh                     [40]
           00104069 00              undefine  00h                     [41]
           0010406a 00              undefine  00h                     [42]
           0010406b 00              undefine  00h                     [43]

           0010406c 39              undefine  39h                     [44]
           0010406d 00              undefine  00h                     [45]
           0010406e 00              undefine  00h                     [46]
           0010406f 00              undefine  00h                     [47]

           00104070 5f              undefine  5Fh                     [48]
           00104071 00              undefine  00h                     [49]
           00104072 00              undefine  00h                     [50]
           00104073 00              undefine  00h                     [51]

           00104074 64              undefine  64h                     [52]
           00104075 00              undefine  00h                     [53]
           00104076 00              undefine  00h                     [54]
           00104077 00              undefine  00h                     [55]

           00104078 30              undefine  30h                     [56]
           00104079 00              undefine  00h                     [57]
           0010407a 00              undefine  00h                     [58]
           0010407b 00              undefine  00h                     [59]

           0010407c 77              undefine  77h                     [60]
           0010407d 00              undefine  00h                     [61]
           0010407e 00              undefine  00h                     [62]
           0010407f 00              undefine  00h                     [63]

           00104080 6e              undefine  6Eh                     [64]
           00104081 00              undefine  00h                     [65]
           00104082 00              undefine  00h                     [66]
           00104083 00              undefine  00h                     [67]

           00104084 5f              undefine  5Fh                     [68]
           00104085 00              undefine  00h                     [69]
           00104086 00              undefine  00h                     [70]
           00104087 00              undefine  00h                     [71]

           00104088 74              undefine  74h                     [72]
           00104089 00              undefine  00h                     [73]
           0010408a 00              undefine  00h                     [74]
           0010408b 00              undefine  00h                     [75]

           0010408c 68              undefine  68h                     [76]
           0010408d 00              undefine  00h                     [77]
           0010408e 00              undefine  00h                     [78]
           0010408f 00              undefine  00h                     [79]

           00104090 33              undefine  33h                     [80]
           00104091 00              undefine  00h                     [81]
           00104092 00              undefine  00h                     [82]
           00104093 00              undefine  00h                     [83]

           00104094 5f              undefine  5Fh                     [84]
           00104095 00              undefine  00h                     [85]
           00104096 00              undefine  00h                     [86]
           00104097 00              undefine  00h                     [87]

           00104098 73              undefine  73h                     [88]
           00104099 00              undefine  00h                     [89]
           0010409a 00              undefine  00h                     [90]
           0010409b 00              undefine  00h                     [91]

           0010409c 79              undefine  79h                     [92]
           0010409d 00              undefine  00h                     [93]
           0010409e 00              undefine  00h                     [94]
           0010409f 00              undefine  00h                     [95]

           001040a0 73              undefine  73h                     [96]
           001040a1 00              undefine  00h                     [97]
           001040a2 00              undefine  00h                     [98]
           001040a3 00              undefine  00h                     [99]

           001040a4 63              undefine  63h                     [100]
           001040a5 00              undefine  00h                     [101]
           001040a6 00              undefine  00h                     [102]
           001040a7 00              undefine  00h                     [103]

           001040a8 34              undefine  34h                     [104]
           001040a9 00              undefine  00h                     [105]
           001040aa 00              undefine  00h                     [106]
           001040ab 00              undefine  00h                     [107]

           001040ac 6c              undefine  6Ch                     [108]
           001040ad 00              undefine  00h                     [109]
           001040ae 00              undefine  00h                     [110]
           001040af 00              undefine  00h                     [111]

           001040b0 6c              undefine  6Ch                     [112]
           001040b1 00              undefine  00h                     [113]
           001040b2 00              undefine  00h                     [114]
           001040b3 00              undefine  00h                     [115]

           001040b4 35              undefine  35h                     [116]
           001040b5 00              undefine  00h                     [117]
           001040b6 00              undefine  00h                     [118]
           001040b7 00              undefine  00h                     [119]

           001040b8 7d              undefine  7Dh                     [120]
           001040b9 00              undefine  00h                     [121]
           001040ba 00              undefine  00h                     [122]
           001040bb 00              undefine  00h                     [123]

           001040bc 00              undefine  00h                     [124]
           001040bd 00              undefine  00h                     [125]
           001040be 00              undefine  00h                     [126]
           001040bf 00              undefine  00h                     [127]

```


```text
7B 00 00 00:
0x7B = { (Dezimal 123)

62 00 00 00:
0x62 = b (Dezimal 98)

72 00 00 00:
0x72 = r (Dezimal 114)

33 00 00 00:
0x33 = 3 (Dezimal 51)

34 00 00 00:
0x34 = 4 (Dezimal 52)

6B 00 00 00:
0x6B = k (Dezimal 107)

31 00 00 00:
0x31 = 1 (Dezimal 49)

6E 00 00 00:
0x6E = n (Dezimal 110)

39 00 00 00:
0x39 = 9 (Dezimal 57)

5F 00 00 00:
0x5F = _ (Dezimal 95)

64 00 00 00:
0x64 = d (Dezimal 100)

30 00 00 00:
0x30 = 0 (Dezimal 48)

77 00 00 00:
0x77 = w (Dezimal 119)

6E 00 00 00:
0x6E = n (Dezimal 110)

5F 00 00 00:
0x5F = _ (Dezimal 95)

74 00 00 00:
0x74 = t (Dezimal 116)

68 00 00 00:
0x68 = h (Dezimal 104)

33 00 00 00:
0x33 = 3 (Dezimal 51)

5F 00 00 00:
0x5F = _ (Dezimal 95)

73 00 00 00:
0x73 = s (Dezimal 115)

79 00 00 00:
0x79 = y (Dezimal 121)

73 00 00 00:
0x73 = s (Dezimal 115)

63 00 00 00:
0x63 = c (Dezimal 99)

34 00 00 00:
0x34 = 4 (Dezimal 52)

6C 00 00 00:
0x6C = l (Dezimal 108)

6C 00 00 00:
0x6C = l (Dezimal 108)

35 00 00 00:
0x35 = 5 (Dezimal 53)

7D 00 00 00:
0x7D = } (Dezimal 125)
```

## Rekonstruiertes Ergebnis
Jetzt wo ich alle Bytes rekonstruiert habe kommt man auf den Schluss:

```text
HTB{br34k1n9_d0wn_th3_sysc4ll5}
```

Ich veröffentliche nur Inhalte, deren Veröffentlichung durch die jeweilige Plattform erlaubt ist. Challenge-Binaries, Flags oder andere geschützte Dateien werden nicht ohne entsprechende Erlaubnis in das Repository aufgenommen.
