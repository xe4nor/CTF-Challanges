# THM Reverse Engineering – `ELF Room Crackme3`

> **Plattform:** TryHackMe

> **Kategorie:** Reverse Engineering

> **Schwierigkeit:** Easy

> **Architektur:** x86 i386

> **Dateityp:** ELF

> **Tools:** file strings ghidra

> **Status:** Solved

---

# Übersicht

Ziel der Challenge ist es das Programmverhalten zu verstehen und die Flagge zu bekommen.

---

# 1. Erste Analyse der Binary

```bash
file crackme3
```

## Ausgabe

```text
crackme3: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV)
```

## Erkenntnisse

* ELF
* 32-Bit

---

# 2. Strings untersuchen

```bash
strings crackme3
```

## Interessante Strings

```text
Usage: %s PASSWORD
malloc failed
[REDACTED_BASE64_VALUE]
Correct password!
Come on, even my aunt Mildred got this one!
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

## Beobachtungen

* die codierten zeichen könnten das passwort oder die flagge sein.
* es scheint eine Passworteingabe/Authentifizierung zu geben.
* sieht sehr stark nach base64 aus.
---

# 3. Programmverhalten untersuchen

```bash
sudo chmod +x crackme3
```

## Eingabe

```text
./crackme3
```

## Ausgabe

```text
Usage: ./crackme3 PASSWORD

```

## Beobachtungen
* wir brauchen das Passwort um uns zu authentifizieren um die flagge zu bekommen 
* vermutlich ist das Passwort in base64 codiert, trotzdem schaue ich mir das ganze mal mit ghidra an.
---

# 4. Analyse mit Ghidra

## `processEntry`

als ich die Datei in ghidra geöffnet habe wurde ich zuerst zur processEntry funktion gebracht 

```c
void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined1 auStack_4 [4];
  
  __libc_start_main(FUN_080484f4,param_2,&stack0x00000004,FUN_08048d90,FUN_08048e00,param_1,
                    auStack_4);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

## Beobachtungen

Das ist der Startup code der main() aufruft vermutlich FUN_080484f4

## Interessante Funktionen

* FUN_080484f4

## `FUN_080484f4`

Ich springe in die FUN_080484f4 und sehe:

```c
undefined4 FUN_080484f4(int param_1,undefined4 *param_2)

{
  char *__s;
  size_t sVar1;
  char *__s_00;
  int iVar2;
  
  if (param_1 == 2) {
    __s = (char *)param_2[1];
    sVar1 = strlen(__s);
    __s_00 = malloc(sVar1 * 2);
    if (__s_00 == (char *)0x0) {
      fwrite("malloc failed\n",0xe,1,stderr);
    }
    else {
      sVar1 = strlen(__s);
      FUN_080486b0(__s,__s_00,sVar1,0);
      sVar1 = strlen(__s_00);
      if ((sVar1 == 0x40) &&
         (iVar2 = strcmp(__s_00,"[REDACTED_BASE64_VALUE]"),
         iVar2 == 0)) {
        puts("Correct password!");
        return 0;
      }
      puts("Come on, even my aunt Mildred got this one!");
    }
  }
  else {
    fprintf(stderr,"Usage: %s PASSWORD\n",*param_2);
  }
  return 0xffffffff;
}
```
## Beobachtungen

Nachdem ich schon das Programm im vorhinein gestartet habe kann man sicher sagen das hier die main() ist.
Als erstes werde ich die variablen benennen um den code etwas leichter lesbarer zu machen.

## Aufgeräumt

```c

undefined4 main(int argc,char **argv)

{
  size_t password_length;
  char *buffer;
  int compare_result;
  char *input_password;
  
  if (argc == 2) {
    input_password = argv[1];
    password_length = strlen(input_password);
    buffer = malloc(password_length * 2);
    if (buffer == (char *)0x0) {
      fwrite("malloc failed\n",0xe,1,stderr);
    }
    else {
      password_length = strlen(input_password);
      FUN_080486b0(input_password,buffer,password_length,0);
      password_length = strlen(buffer);
      if ((password_length == 0x40) &&
         (compare_result =
               strcmp(buffer,"[REDACTED_BASE64_VALUE]"),
         compare_result == 0)) {
        puts("Correct password!");
        return 0;
      }
      puts("Come on, even my aunt Mildred got this one!");
    }
  }
  else {
    fprintf(stderr,"Usage: %s PASSWORD\n",*argv);
  }
  return 0xffffffff;
}


```
## Beobachtungen

als ich den code umbenannt habe und lesbarer habe ich die funktion FUN_080486b0 entdeckt diese werde ich mir auch anschauen da sie direkt mit dem passwort interagiert.

## `FUN_080486b0`

```c

int FUN_080486b0(int param_1,int param_2,uint param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  int local_2c;
  int local_1c;
  uint local_18;
  
  local_2c = 0;
  uVar2 = param_3 % 3;
  if (param_2 == 0) {
    local_1c = (param_3 / 3) * 4;
    if (uVar2 != 0) {
      local_1c = local_1c + 4;
    }
    if (param_4 != 0) {
      local_1c = local_1c + param_3 / 0x39;
    }
  }
  else {
    local_1c = 0;
    for (local_18 = 0; local_18 < (param_3 / 3) * 3; local_18 = local_18 + 3) {
      *(char *)(param_2 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [*(byte *)(param_1 + local_18) >> 2];
      *(char *)(local_1c + 1 + param_2) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(uint)(*(byte *)(param_1 + 1 + local_18) >> 4) |
            (*(byte *)(param_1 + local_18) & 3) << 4];
      *(char *)(local_1c + 2 + param_2) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(uint)(*(byte *)(local_18 + 2 + param_1) >> 6) |
            (*(byte *)(local_18 + 1 + param_1) & 0xf) * 4];
      *(char *)(local_1c + 3 + param_2) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [*(byte *)(local_18 + 2 + param_1) & 0x3f];
      uVar1 = (local_1c - local_2c) + 4;
      if ((uVar1 == (uVar1 / 0x4c) * 0x4c) && (param_4 != 0)) {
        *(undefined1 *)(param_2 + 4 + local_1c) = 10;
        local_1c = local_1c + 1;
        local_2c = local_2c + 1;
      }
      local_1c = local_1c + 4;
    }
    if (uVar2 == 1) {
      *(char *)(param_2 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)*(byte *)(param_1 + local_18) >> 2];
      *(char *)(param_2 + 1 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(*(byte *)(param_1 + local_18) & 3) * 0x10];
      *(undefined1 *)(param_2 + 2 + local_1c) = 0x3d;
      *(undefined1 *)(param_2 + 3 + local_1c) = 0x3d;
      local_1c = local_1c + 4;
    }
    else if (uVar2 == 2) {
      *(char *)(param_2 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)*(byte *)(param_1 + local_18) >> 2];
      *(char *)(param_2 + 1 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)*(byte *)(param_1 + 1 + local_18) >> 4 |
            (*(byte *)(param_1 + local_18) & 3) << 4];
      *(char *)(param_2 + 2 + local_1c) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(*(byte *)(param_1 + 1 + local_18) & 0xf) * 4];
      *(undefined1 *)(param_2 + 3 + local_1c) = 0x3d;
      local_1c = local_1c + 4;
    }
  }
  return local_1c;
}


```
## Beobachtungen

ich werde den code auch umbennen um ihn lesbarer zu machen.

## FUN_080486b0 Aufgeräumt

```c

int base64_encode(char *input_password,char *buffer,uint password_length,int param_4)

{
  uint uVar1;
  uint remaining_bytes;
  int local_2c;
  int output_length;
  uint local_18;
  
  local_2c = 0;
  remaining_bytes = password_length % 3;
  if (buffer == (char *)0x0) {
    output_length = (password_length / 3) * 4;
    if (remaining_bytes != 0) {
      output_length = output_length + 4;
    }
    if (param_4 != 0) {
      output_length = output_length + password_length / 0x39;
    }
  }
  else {
    output_length = 0;
    for (local_18 = 0; local_18 < (password_length / 3) * 3; local_18 = local_18 + 3) {
      buffer[output_length] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(byte)input_password[local_18] >> 2];
      buffer[output_length + 1] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(uint)((byte)input_password[local_18 + 1] >> 4) |
            ((byte)input_password[local_18] & 3) << 4];
      buffer[output_length + 2] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(uint)((byte)input_password[local_18 + 2] >> 6) |
            ((byte)input_password[local_18 + 1] & 0xf) * 4];
      buffer[output_length + 3] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(byte)input_password[local_18 + 2] & 0x3f];
      uVar1 = (output_length - local_2c) + 4;
      if ((uVar1 == (uVar1 / 0x4c) * 0x4c) && (param_4 != 0)) {
        buffer[output_length + 4] = '\n';
        output_length = output_length + 1;
        local_2c = local_2c + 1;
      }
      output_length = output_length + 4;
    }
    if (remaining_bytes == 1) {
      buffer[output_length] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18] >> 2];
      buffer[output_length + 1] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [((byte)input_password[local_18] & 3) * 0x10];
      buffer[output_length + 2] = '=';
      buffer[output_length + 3] = '=';
      output_length = output_length + 4;
    }
    else if (remaining_bytes == 2) {
      buffer[output_length] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18] >> 2];
      buffer[output_length + 1] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18 + 1] >> 4 |
            ((byte)input_password[local_18] & 3) << 4];
      buffer[output_length + 2] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [((byte)input_password[local_18 + 1] & 0xf) * 4];
      buffer[output_length + 3] = '=';
      output_length = output_length + 4;
    }
  }
  return output_length;
}

```
## Beobachtungen

Die funktion ist ein Base64 encoder und kodiert die eingabe des passwort und gibt sie im anschluss an den buffer zurück damit man sie später mit strcmp vergleichen kann.

Man sieht anhand mehrer Faktoren das es ein base64 Encoder ist.

1. Sie verwendet das Typische base64 Alphabet (`A-Z`, `a-z`, `0-9`, `+`, `/`)

2. Die Eingabe wird in Blöcken von 3 Bytes verarbeitet:
```c
remaining_bytes = input_length % 3;
```
 aus denen dann 4 ausgabezeichen erzeugt werden, bei einer eingabelänge die nicht durch 3 geteilt werden wird die ausgabe mit einem = ausgefüllt das kann man gut in diesem code abschnitt sehen:

 ```c
 if (remaining_bytes == 1) {
      buffer[output_length] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18] >> 2];
      buffer[output_length + 1] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [((byte)input_password[local_18] & 3) * 0x10];
      buffer[output_length + 2] = '=';
      buffer[output_length + 3] = '=';
      output_length = output_length + 4;
    }
    else if (remaining_bytes == 2) {
      buffer[output_length] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18] >> 2];
      buffer[output_length + 1] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [(int)(uint)(byte)input_password[local_18 + 1] >> 4 |
            ((byte)input_password[local_18] & 3) << 4];
      buffer[output_length + 2] =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
           [((byte)input_password[local_18 + 1] & 0xf) * 4];
      buffer[output_length + 3] = '=';
      output_length = output_length + 4;
    }
 ```

# 5. Eingabe / Lösung rekonstruieren

Da die Benutzereingabe mit Base64 kodiert und anschließend mit einem
fest im Binary hinterlegten Wert verglichen wird, lässt sich die
erwartete Eingabe durch Dekodieren dieses Wertes rekonstruieren.

> Der konkrete Base64-Wert und das daraus resultierende Passwort wurden
> entfernt, um die aktive Challenge nicht zu spoilern.

Nach Verwendung der rekonstruierten Eingabe bestätigt das Programm
die erfolgreiche Analyse:

```text
Correct password!
```
Damit ist die Challenge fertig und die Flagge eingereicht.

## Hinweis

Ich veröffentliche nur Inhalte, deren Veröffentlichung durch die jeweilige Plattform erlaubt ist. Challenge-Binaries, Flags oder andere geschützte Dateien werden nicht ohne entsprechende Erlaubnis in das Repository aufgenommen.
