![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Curveware</font>

​	20<sup>th</sup> April 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `rasti`

​	Difficulty: <font color=red>Hard</font>

​	Classification: Official

# Synopsis

- `Curveware` is a hard crypto challenge in which the players must decompile the provided ransomware and understand how the provided repository was encrypted and how the custom ECDSA-based signature scheme works. Once they identify the partial nonce leakage and that the same private key was used to create the signatures and encrypt the files, they should apply lattice reduction attack to recover the private key and decrypt the files.

## Description

- A compromised diagnostics terminal from a classified Volnayan facility revealed a highly polished encryption tool-one that locks data with mathematical precision and even tags each action with a cryptographic seal. But traces of old testing builds suggest overconfidence.



## Skills Required

- Basic knowledge of decompilation

- Basic knowledge of how to use decompilation tools such as IDA, Binary Ninja, Ghidra etc

- Good C source code auditing

- Source code auditing of open source cryptographic libraries

- Good knowledge of elliptic curve-based signature schemes

- Good knowledge of how ECDSA and its variants work

- Familiar with SageMath

  

## Skills Learned

- Understand the vulnerability that occurs when there is even a small nonce leakage
- Understand how to convert ECDSA-like signature schemes into an HNP problem
- Know how to construct lattice bases for applying lattice reduction techniques
- Learn how to translate decompiled code into mathematical equations
- Learn how to apply LLL using SageMath

# Enumeration

Let us run `unzip -l crypto_curveware.zip` to preview the contents of the provided downloadable zip file.

```
$ unzip -l crypto_curveware.zip

Archive:  crypto_curveware.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  05-12-2025 13:37   crypto_curveware/
        0  05-12-2025 13:37   crypto_curveware/business-ctf-2025-dev/
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/curveware/
      144  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/curveware/flag.txt.vlny0742e9337a
     1136  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/curveware/poc.py.vlnyc2b7865f66
      464  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/curveware/README.md.vlnya68395585b
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/curveware/task.txt.vlnyde7ca30df0
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/early-bird/
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/early-bird/flag.txt.vlny4a13aac40e
      464  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/early-bird/README.md.vlny1d615936ca
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/early-bird/task.txt.vlny152e012de7
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/hidden-handshake/
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/hidden-handshake/flag.txt.vlny483931d01c
      480  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/hidden-handshake/README.md.vlnyda959133e7
      192  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/hidden-handshake/task.txt.vlny37927847f9
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/phoenix-zero-trust/
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/phoenix-zero-trust/flag.txt.vlny42db696fd5
      480  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/phoenix-zero-trust/README.md.vlnyd38f3522f4
      192  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/phoenix-zero-trust/task.txt.vlny383594e3ef
        0  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/transcoded/
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/transcoded/flag.txt.vlny048404e260
      480  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/transcoded/README.md.vlnyd323bde76d
      176  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/crypto/transcoded/task.txt.vlnye5c611e15a
     1056  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/README.md.vlny311cf84811
      704  05-12-2025 13:34   crypto_curveware/business-ctf-2025-dev/scenario.md.vlnycba760a47c
   201736  05-12-2025 13:35   crypto_curveware/curveware
---------                     -------
   208760                     27 files
```

From the filename extensions, we deduce that a ransomware potentially encrypted these files, appending a `.vlny` extension along with a few hex characters that seem random. For the record, `.vlny` stands for `Volnaya`. Let us run `file curveware` to find more information about the provided ransomware.

```
$ file curveware
curveware: PE32+ executable (console) x86-64, for MS Windows
```

It appears to be a x86-64 PE executable which implies that it targets Windows users. Let us preview the raw bytes of one of these encrypted files just to make sure there is no significant hidden information inside.

```
$ xxd scenario.md.vlnycba760a47c
00000000: b41d 3b6f df0d 6fa2 d3ad 4f3a 5a83 1519  ..;o..o...O:Z...
00000010: b07d ad50 8204 a1f1 53f5 e0dd 3812 be89  .}.P....S...8...
00000020: 3431 1ff0 a32f 562a ad01 0633 8bb8 7da4  41.../V*...3..}.
00000030: fbb2 aabd 4836 235e cb26 0ff5 a666 dedb  ....H6#^.&...f..
00000040: bb02 cc64 910d a180 f865 5d97 c9f5 3a32  ...d.....e]...:2
00000050: f722 5bcc 9b3c 6dee 1426 577f e69b c319  ."[..<m..&W.....
00000060: 8391 f841 4aa6 ef1f 567b 5004 095d 73da  ...AJ...V{P..]s.
00000070: bb14 b982 5f13 f8cf d282 03ac 8d9f 3e0e  ...._.........>.
00000080: 1b7d f017 6b88 b0eb ac21 f798 da22 d4ec  .}..k....!..."..
00000090: 0496 9824 afc2 855e efe8 adef 6382 ff6d  ...$...^....c..m
000000a0: 8901 74af ad98 deb5 c707 298d d809 db40  ..t.......)....@
000000b0: 5047 3c98 058a fde0 1c04 4768 6ede 3b3b  PG<.......Ghn.;;
000000c0: 273a 49d1 162c 080b f9ac a84b 3390 b5fa  ':I..,.....K3...
000000d0: 6099 2768 7479 ad76 ffbe d82e 32e1 4c04  `.'hty.v....2.L.
000000e0: 7b47 5f07 04aa b241 f667 35ea 080e f119  {G_....A.g5.....
000000f0: 4c31 a48c 1a9d 5fee fc22 7bc9 b5a3 270c  L1...._.."{...'.

... REDACTED ...
```

The files' contents look encrypted. All that is left to do is import the PE binary into a tool of our choice and let the decompiler do its magic.



## Analyzing the source code

For this writeup, we will use the open source tool Ghidra.

We will analyze the source code in chunks. Let us first jump to the main function which begins with the following:

```c
local_bcc = 0x80;
GetUserNameA(local_ba8,&local_bcc);
iVar1 = strcmp(local_ba8,"htb_fhjxjxjaxkx");
if (iVar1 == 0) {
		GetCurveParameters((undefined1 *)local_9e8);
  	... REDACTED ...
}
exit(1);
```

[`GetUserNameA`][2] is a function from the Windows library `advapi32.dll`. The MSDN docs are extremely useful and we will use them as our core documentation resource.

> Retrieves the name of the user associated with the current thread.

The username is then checked with the hardcoded username `htb_fhjxjxjaxkx` and if it does not match, it exits. Apparently, this works as a safety net for the users that might run the ransomware by mistake. In other case, their files would be actually encrypted and even though the challenge is designed in a way that decryption is doable, it would be bad user experience. In case a player really knows what they are doing, they can patch this call and be able to debug the ransomware, if needed.

A function of interest is `GetCurveParameters` which looks like an initialization function for some of the cryptographic components of the malware. This function is pretty short so let us paste it below:

```c
void GetCurveParameters(undefined1 *param_1)
{
  int iVar1;
  undefined8 uVar2;
  longlong *local_10;
  
  uVar2 = ec_get_curve_params_by_type(4,&local_10);
  if (((int)uVar2 == 0) && (local_10 != (longlong *)0x0)) {
    iVar1 = import_params(param_1,local_10);
    if (iVar1 == 0) {
      return;
    }
    exit(2);
  }
  exit(1);
}
```

`ec_get_curve_params_by_type` and `import_params` are not functions defined by the malware author but they appear to be part of an open source cryptographic library called `libecc` responsible for doing elliptic curve arithmetic. For example, the implementation of `ec_get_curve_params_by_type` can be found [here][3]. Surprisingly, Ghidra directly identifies that the curve used is `SECP256R1`:

```c
undefined8 ec_get_curve_params_by_type(int param_1, undefined8 *param_2)
{
  undefined8 uVar1;
  uint local_c;
  
  if ((param_1 == 4) && (param_2 != (undefined8 *)0x0)) {
    uVar1 = local_strlen("SECP256R1",&local_c);
    if ((int)uVar1 == 0) {
      if (local_c != 9) {
        return 0xffffffff;
      }
      *param_2 = &secp256r1_str_params;
    }
    return uVar1;
  }
  return 0xffffffff;
}
```

But this depends on the version of the decompiler. We will show how to figure this out manually:

### Getting the curve parameters

The first argument of `ec_get_curve_params_by_type` is the value `4`. By looking at github, the first parameter's type if a custom-defined enum, namely `ec_curve_type`. With the help of GitHub search we follow the enum name and end up in `lib_ecc_types.h` [where][4] we see that the value `4` actually corresponds to the curve `SECP256R1`. What is left is research online for the parameters of this curve. [`neuromancer.sk`][5] is usually a good website that contains this type of information.

Let us fire up a SageMath shell and define the curve:

```python
sage: p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
sage: K = GF(p)
sage: a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
sage: b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
sage: E = EllipticCurve(K, (a, b))
sage: G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
sage: q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
sage: E.set_order(q)
```

Having this information, we proceed with the source code analysis.

```c
get_random(local_bc8,0x20);
```

`get_random` is part of the `libecc` library and is implemented [here][6]. 32 random bytes are generated using the windows API `CryptGenRandom`.

### Analyzing the ransomware main

The core logic of the ransomware is the following:

```c
pcVar3 = getenv("USERPROFILE");
_Count = strlen(pcVar3);
_Dest = (char *)calloc(_Count + 2,1);
_Str1 = local_b28.cFileName;
strncpy(_Dest,pcVar3,_Count);
sVar4 = strlen(_Dest);
pcVar3 = _Dest + sVar4;
pcVar3[0] = '\\';
pcVar3[1] = '*';
pcVar3[2] = '\0';
hFindFile = FindFirstFileA(_Dest,&local_b28);
do {
    iVar1 = strcmp(_Str1,".");
    if (iVar1 != 0) {
        iVar1 = strcmp(_Str1,"..");
        if ((iVar1 != 0) && (((byte)local_b28.dwFileAttributes & 0x10) != 0)) {
            _Count_00 = strlen(_Str1);
            sVar4 = _Count + _Count_00 + 1;
            pcVar3 = (char *)calloc(_Count + _Count_00 + 2,1);
            strncat(pcVar3,_Dest,_Count);
            sVar5 = strlen(pcVar3);
            (pcVar3 + sVar5)[0] = '\\';
            (pcVar3 + sVar5)[1] = '\0';
            strncat(pcVar3 + _Count + 1,_Str1,_Count_00);
            uVar6 = is_repository(pcVar3,sVar4);
            if ((char)uVar6 != '\0') {
                puVar8 = local_9e8;
                puVar9 = local_1578;
                for (lVar7 = 0x134; lVar7 != 0; lVar7 = lVar7 + -1) {
                    *puVar9 = *puVar8;
                    puVar8 = puVar8 + 1;
                    puVar9 = puVar9 + 1;
                }
                process_directory(pcVar3,sVar4,local_bc8,local_1578);
            }
            free(pcVar3);
        }
    }
		BVar2 = FindNextFileA(hFindFile,&local_b28);
} while (BVar2 != 0);
FindClose(hFindFile);
return 0;
```

The ransomware does the following:

1. It iterates through the entire user's profile directory.
2. It skips all files that are not directories. We understand this from the `dwFileAttributes` field of the `FindFileData` structure. This field is a dword that works as a multi-flag. The constants for these flags are found in the MSDN [docs][7]. The flag `0x10` corresponds to the `FILE_ATTRIBUTE_DIRECTORY` value and if it is set, this indicates that the current file is a directory.
3. Then, each directory is passed into `is_repository` which we assume that returns True/False depending on whether the specified directory is a valid git repository. Further analysis of this function will be performed later.
4. If the current directory is a repository, `process_directory` is called which will also be analyzed later.

```c
undefined8 is_repository(char *param_1,size_t param_2)
{
  BOOL BVar1;
  char *_Dest;
  size_t sVar2;
  HANDLE hFindFile;
  undefined4 extraout_var;
  _WIN32_FIND_DATAA local_158;
  
  _Dest = (char *)malloc(param_2 + 6);
  strncpy(_Dest,param_1,param_2);
  _Dest[param_2] = '\0';
  sVar2 = strlen(_Dest);
  builtin_strncpy(_Dest + sVar2,"\\.git",6);
  hFindFile = FindFirstFileA(_Dest,&local_158);
  BVar1 = FindClose(hFindFile);
  return CONCAT71((int7)(CONCAT44(extraout_var,BVar1) >> 8),hFindFile != (HANDLE)0xffffffffffffffff)
  ;
}
```

As we guessed, this function checks for the existence of the folder `.git` and returns `True` if it does exist, otherwise `False`.

### Analyzing `process_directory`

This function might appear big but what it does is recursively iterate through the repository directory, ignoring the `.git` folder, and further process each file. For each file, it does the following:

```c
hFile = CreateFileA(pcVar7,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
if (hFile == (HANDLE)0xffffffffffffffff) {
		exit(3);
}
DVar3 = GetFileSize(hFile,(LPDWORD)0x0);
lpBuffer_00 = calloc((ulonglong)(DVar3 + 1),1);
BVar4 = ReadFile(hFile,lpBuffer_00,DVar3,&local_1e4,(LPOVERLAPPED)0x0);
if (BVar4 == 0) {
		exit(4);
}
encrypt_data(lpBuffer_00,local_1e4,param_3,(longlong *)&local_1d8,&local_1dc,&local_1d0);
lVar10 = local_1d0;
lpBuffer = local_1d8;
DVar3 = local_1dc;
sign_data(local_1c8,(longlong)param_4,(longlong)param_3,(longlong)local_1d8,local_1dc, local_1d0);
```

It reads the file data into the `lpBuffer_00` variable and passes it to `encrypt_data`. After `ReadFile`, `NumberOfBytesRead` contains the number of bytes read from the file handle. It is always a good practice to rename variables so that we have a much more clear idea of what the code does.

### Analyzing `encrypt_data`

We now further inspect what `encrypt_data` does:

```c

void encrypt_data(void *Plaintext,uint PlaintextSize,byte *param_3,longlong *param_4,uint *param_5,
                 undefined8 *PlaintextHash)
{
    undefined8 *puVar1;
    void *pvVar2;
    undefined1 *PlaintextSHA256Hash;
    uint uVar3;
    uint uVar4;
    ulonglong uVar5;
    uint uVar6;
    undefined8 local_158;
    undefined8 uStack_150;
    byte local_148 [264];

    uVar6 = 0x10 - (PlaintextSize & 0xf);
    uVar3 = (uVar6 & 0xff) + PlaintextSize;
    *param_5 = uVar3;
    pvVar2 = calloc((ulonglong)uVar3,1);
    *param_4 = (longlong)pvVar2;
    memcpy(pvVar2,Plaintext,(ulonglong)PlaintextSize);
    PlaintextSHA256Hash = (undefined1 *)calloc(0x20,1);
    *PlaintextHash = PlaintextSHA256Hash;
    sha256((longlong)Plaintext,PlaintextSize,PlaintextSHA256Hash);
    uVar5 = (ulonglong)PlaintextSize;
    do {
        uVar4 = (int)uVar5 + 1;
        *(char *)(*param_4 + uVar5) = (char)uVar6;
        uVar5 = (ulonglong)uVar4;
    } while (uVar3 != uVar4);
    get_random((BYTE *)&local_158,0x10);
    AES_init_ctx_iv(local_148,param_3,&local_158);
    AES_CBC_encrypt_buffer((longlong)local_148,(byte *)*param_4,(byte *)(ulonglong)*param_5);
    uVar3 = *param_5;
    pvVar2 = (void *)*param_4;
    *param_5 = uVar3 + 0x10;
    pvVar2 = realloc(pvVar2,(ulonglong)(uVar3 + 0x11));
    uVar3 = *param_5;
    *param_4 = (longlong)pvVar2;
    puVar1 = (undefined8 *)((longlong)pvVar2 + (ulonglong)(uVar3 - 0x10));
    *puVar1 = local_158;
    puVar1[1] = uStack_150;
    return;
}
```

The lines:

```c
uVar6 = 0x10 - (PlaintextSize & 0xf);
uVar3 = (uVar6 & 0xff) + PlaintextSize;
pvVar2 = calloc((ulonglong)uVar3,1);
```

are responsible for calculating the PKCS#7 padding byte of the plaintext. Therefore, `uVar3` stores the size of the updated, padded plaintext size and `pvVar2` the padded plaintext.

Then, the plaintext file data are SHA256-hashed:

```c
PlaintextSHA256Hash = (undefined1 *)calloc(0x20,1);
*PlaintextHash = PlaintextSHA256Hash;
sha256((longlong)Plaintext,PlaintextSize,PlaintextSHA256Hash);
```

and the result hash is stored at `PlaintextSHA256Hash`. Then, the actual PKCS#7 padding process is performed:

```c
PlaintextSizeCopy = (ulonglong)PlaintextSize;
do {
    PlaintextSizeIterator = (int)PlaintextSizeCopy + 1;
    *(char *)(*PaddedPlaintextParam + PlaintextSizeCopy) = (char)PaddingByte;
    PlaintextSizeCopy = (ulonglong)PlaintextSizeIterator;
} while (PaddedPlaintextSize != PlaintextSizeIterator);
```

Then, there is the meat of the current function we are analyzing:

```c
get_random((BYTE *)&local_158,0x10);
AES_init_ctx_iv(local_148,param_3,&local_158);
AES_CBC_encrypt_buffer((longlong)local_148,(byte *)*PaddedPlaintextParam, (byte *)(ulonglong)*PaddedPlaintextSizeParam);
```

With some online research, we find out that the symbols `AES_init_ctx_iv` and `AES_CBC_encrypt_buffer` belong to an open source AES implementation, that is [`tiny-AES-c`][8]. The second argument of `AES_init_ctx_iv` corresponds to the encryption key and the third to the IV. This helps us do some effective renaming to the Ghidra decompilation.

Finally:

```c
PaddedPlaintextSize = *PaddedPlaintextSizeParam;
PaddedPlaintext = (void *)*PaddedPlaintextParam;
*PaddedPlaintextSizeParam = PaddedPlaintextSize + 0x10;
PaddedPlaintext = realloc(PaddedPlaintext,(ulonglong)(PaddedPlaintextSize + 0x11));
PaddedPlaintextSize = *PaddedPlaintextSizeParam;
*PaddedPlaintextParam = (longlong)PaddedPlaintext;
puVar1 = (undefined8 *)((longlong)PaddedPlaintext + (ulonglong)(PaddedPlaintextSize - 0x10));
*puVar1 = IV;
puVar1[1] = uStack_150;
```

these lines are responsible for appending the IV to the encrypted data.

Back to `process_directory`, and having applied some proper variable renaming, the decompilation now is much more clear than before:

```c
encrypt_data(filePlaintextData,filePlaintextDataSize,AES_KEY,(longlong *)&EncryptedDataBuffer, &EncryptedDataSize,&PlaintextHash);
lVar10 = PlaintextHash;
lpBuffer = EncryptedDataBuffer;
DVar3 = EncryptedDataSize;
sign_data(local_1c8,(longlong)CurveParameters,(longlong)AES_KEY,(longlong)EncryptedDataBuffer, EncryptedDataSize,PlaintextHash);
```

Before analyzing `sign_data`, we notice something odd. The AES key that was used for encryption is also passed as an argument for signing data. It turns out that this is crucial for managing to decrypt the encrypted files.

### Analyzing `sign_data`

```c
void sign_data(undefined1 *param_1,longlong CurveParameters,longlong AES_KEY,
              longlong EncryptedDataBuffer,uint EncryptedDataSize,longlong PlaintextHash)
{
    undefined1 local_678 [32];
    undefined1 local_658 [16];
    undefined8 local_648;
    undefined8 uStack_640;

    ... REDACTED variable declaration ...
  
    sha256(EncryptedDataBuffer,EncryptedDataSize,EncryptedDataHash);
    nn_init_from_buf((undefined1 (*) [16])EncryptedDataHash_nn,(longlong)EncryptedDataHash,0x20);
    nn_init_from_buf((undefined1 (*) [16])AES_KEY_nn,AES_KEY,0x20);
    nn_init_from_buf((undefined1 (*) [16])PlaintextHash_nn,PlaintextHash,0x20);
    local_658._0_8_ = *(undefined8 *)(CurveParameters + 0x6f0);
    local_658._8_8_ = *(undefined8 *)(CurveParameters + 0x6f8);
    local_648 = *(undefined8 *)(CurveParameters + 0x700);
    uStack_640 = *(undefined8 *)(CurveParameters + 0x708);
    local_638 = *(undefined8 *)(CurveParameters + 0x710);
    uStack_630 = *(undefined8 *)(CurveParameters + 0x718);
    local_628 = *(undefined8 *)(CurveParameters + 0x720);
    uStack_620 = *(undefined8 *)(CurveParameters + 0x728);
    local_618 = *(undefined8 *)(CurveParameters + 0x730);
    uStack_610 = *(undefined8 *)(CurveParameters + 0x738);
    local_608 = *(undefined8 *)(CurveParameters + 0x740);
    uStack_600 = *(undefined8 *)(CurveParameters + 0x748);
    local_5f8 = *(undefined8 *)(CurveParameters + 0x750);
    uStack_5f0 = *(undefined8 *)(CurveParameters + 0x758);
    prj_pt_mul((undefined1 (*) [16])local_1c8,(undefined1 (*) [16])PlaintextHash_nn,
               (undefined1 (*) [16])(CurveParameters + 0x560));
    prj_pt_to_aff((undefined1 (*) [16])local_2d8,(undefined1 (*) [16])local_1c8);
    nn_mod_sub((undefined1 (*) [16])local_3b8,(undefined1 (*) [16])EncryptedDataHash_nn,
               (undefined1 (*) [16])local_2d8,&local_658);
    nn_modinv_fermat((undefined1 (*) [16])local_508,(undefined1 (*) [16])AES_KEY_nn,&local_658);
    nn_mod_sub((undefined1 (*) [16])local_498,(undefined1 (*) [16])PlaintextHash_nn,
               (undefined1 (*) [16])local_3b8,&local_658);
    nn_mod_mul((undefined1 (*) [16])local_348,(undefined1 (*) [16])local_508,
               (undefined1 (*) [16])local_498,&local_658);
    nn_export_to_buf(param_1,0x20,(longlong)local_3b8);
    nn_export_to_buf(param_1 + 0x20,0x20,(longlong)local_348);
    return;
}
```

There is a lot going on here. To begin with, `nn_init_from_buf` is a function of the `libecc` library and as the name implies, it receives an unsigned byte string as an argument and converts it to libecc's numeric data type `nn`.

This function accesses some offsets of the `CurveParameters` variable which indicates that `CurveParameters` is a struct. Researching at the online library, it seems that we are right and the structure of the curve parameters is defined [here][9]. However, it is still hard to figure out what each variable is so let us analyze all the function calls one by one.

```c
prj_pt_mul((undefined1 (*) [16])local_1c8,(undefined1 (*) [16])PlaintextHash_nn, (undefined1 (*) [16])(CurveParameters + 0x560));
```

This function multiplies a projective point (basically a point with projective coordinates) with an `nn` number. Based on the structure, the only projective point there, is the curve's generator $G$. Having some experience with other ECDSA-based signature schemes, this is usually the first step for signing; multiplication of the generator $G$ with the nonce $k$​. Apparently, for this challenge, the nonce used is `PlaintextHash_nn`. Then, the projective point is converted to an affine point (a point with affine coordinates).

```c
nn_mod_sub((undefined1 (*) [16])local_3b8,(undefined1 (*) [16])EncryptedDataHash_nn,(undefined1 (*) [16])local_2d8,&local_658);
```

Let us look at the original function's signature:

```c
int nn_mod_sub(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p);
```

This function basically computes the following:
$$
\text{out} = (\text{in}_1 - \text{in}_2) \pmod p
$$
Again, having experience with signature schemes, the modulus used for such operations is usually the order of the group $q$ and not the prime $p$ forming the group. So we assume that the last argument is $q$.

```c
nn_modinv_fermat((undefined1 (*) [16])local_508,(undefined1 (*) [16])AES_KEY_nn,&q);
```

As the name implies, this function computes the modular inverse of the second parameter modulo the last parameter $q$ and stores the result in the first parameter. We can assume that the `AES_KEY` is also used as the private key for signing the data.

```c
nn_mod_mul((undefined1 (*) [16])local_348,(undefined1 (*) [16])local_508,(undefined1 (*) [16])local_498,&local_658);
```

Looking at the signature:

```c
int nn_mod_mul(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p);
```

This function computes:
$$
\text{out} = (\text{in}_1 \cdot \text{in}_2) \pmod p
$$
Knowing this information, we manage to produce the following clean decompilation:

```c
prj_pt_mul((undefined1 (*) [16])Q_proj,(undefined1 (*) [16])nonce,(undefined1 (*) [16])(CurveParameters + 0x560));
prj_pt_to_aff((undefined1 (*) [16])Q_aff,(undefined1 (*) [16])Q_proj);
nn_mod_sub((undefined1 (*) [16])r,(undefined1 (*) [16])EncryptedDataHash_nn,(undefined1 (*) [16])Q_aff,&q);
nn_modinv_fermat((undefined1 (*) [16])aes_key_inv,(undefined1 (*) [16])AES_KEY_nn,&q);
nn_mod_sub((undefined1 (*) [16])nonce_diff_r,(undefined1 (*) [16])nonce,(undefined1 (*) [16])r,&q);
nn_mod_mul((undefined1 (*) [16])s,(undefined1 (*) [16])aes_key_inv,(undefined1 (*) [16])nonce_diff_r,&q);
nn_export_to_buf(param_1,0x20,(longlong)r);
nn_export_to_buf(param_1 + 0x20,0x20,(longlong)s);
```

## Translating the decompiled code into mathematical relations

This code can be mathematically translated into the following signature scheme:
$$
r &=& h - [G \cdot k].\text{x} \pmod q\\
s &=& x^{-1} \cdot (k - r) \pmod q
$$
where:

- $h$ : the hash of the encrypted data
- $k$ : the nonce, which is the plaintext hash of the data
- $[G \cdot k].\text{x}$ : which is the $x$-coordinate of the point $G \cdot k$
- $x$ : the private key used to sign the data. We make an educated guess that this matches the `AES_KEY`
- $q$ : the curve's order
- $G$​ : the generator point of the curve `secp256r1`

We will analyze the scheme more thoroughly later.

## Identifying the partial nonce leakage

There is some code left to analyze which turns out to be crucial for solving the challenge.

```c
*(undefined4 *)_Memory = *(undefined4 *)(lVar10 + 0x1b);
_Memory[4] = *(byte *)(lVar10 + 0x1f);
_Source = (FILE *)calloc(0xb,1);
pbVar11 = _Memory;
pFVar14 = _Source;
do {
    bVar1 = *pbVar11;
    pFVar15 = (FILE *)((longlong)&pFVar14->_ptr + 2);
    pbVar11 = pbVar11 + 1;
    __mingw_snprintf(pFVar14,3,"%02x",(ulonglong)bVar1);
    pFVar14 = pFVar15;
} while (pFVar15 != (FILE *)((longlong)&_Source->_cnt + 2));
DVar5 = SetFilePointer(currentFileHandle,0,(PLONG)0x0,0);
if (DVar5 == 0xffffffff) {
		exit(5);
}
BVar4 = WriteFile(currentFileHandle,DataSignature,0x40,&local_1e0,(LPOVERLAPPED)0x0);
if (BVar4 == 0) {
		exit(6);
}
BVar4 = WriteFile(currentFileHandle,lpBuffer,DVar3,&local_1e0,(LPOVERLAPPED)0x0);
if (BVar4 == 0) {
		exit(7);
}
CloseHandle(currentFileHandle);
_Dest_00 = (char *)calloc(lVar8 + 0x11,1);
strncpy(_Dest_00,pcVar7,lVar8 + 1U);
sVar6 = strlen(_Dest_00);
builtin_strncpy(_Dest_00 + sVar6,".vlny",6);
strncat(_Dest_00,(char *)_Source,10);
BVar4 = MoveFileA(pcVar7,_Dest_00);
```

Either by manual static analysis or with the help of an LLM, one will see that this snippet can be translated to:

```c
BytesExtension[4] = *(byte *)(lVar9 + 0x1f);
HexExtension = (FILE *)calloc(0xb,1);
pbVar10 = BytesExtension;
hexOut = HexExtension;
do {
    bVar1 = *pbVar10;
    pFVar13 = (FILE *)((longlong)&hexOut->_ptr + 2);
    pbVar10 = pbVar10 + 1;
    __mingw_snprintf(hexOut,3,"%02x",(ulonglong)bVar1);
    hexOut = pFVar13;
} while (pFVar13 != (FILE *)((longlong)&HexExtension->_cnt + 2));
DVar5 = SetFilePointer(CurrentFileHandle,0,(PLONG)0x0,0);
if (DVar5 == 0xffffffff) {
    exit(5);
}
BVar4 = WriteFile(CurrentFileHandle,DataSignature,0x40,&NumberOfBytesWritten,(LPOVERLAPPED)0x0);
if (BVar4 == 0) {
    exit(6);
}
BVar4 = WriteFile(CurrentFileHandle,lpBuffer,DVar3,&NumberOfBytesWritten,(LPOVERLAPPED)0x0);
if (BVar4 == 0) {
    exit(7);
}
CloseHandle(CurrentFileHandle);
NewFullFilename = (char *)calloc(lVar7 + 0x11,1);
strncpy(NewFullFilename,FullFilename,lVar7 + 1U);
sVar6 = strlen(NewFullFilename);
builtin_strncpy(NewFullFilename + sVar6,".vlny",6);
strncat(NewFullFilename,(char *)HexExtension,10);
BVar4 = MoveFileA(FullFilename,NewFullFilename);
```

From the line:

```c
WriteFile(CurrentFileHandle,DataSignature,0x40,&NumberOfBytesWritten,(LPOVERLAPPED)0x0);
```

we understand that the 64-byte serialized signature $(r, s)$ is prepended into the output file.

The only mystery left is the hex characters appended right after the string `.vlny`. Either with debugging or static analysis one will see that these hex characters are far from random but in fact they are the last 5 bytes (10 hex characters) of the plaintext hash. This is a technique seen from ransomware authors in the past.

[ 1 ]: https://dogbolt.org/ "Decompiler Explorer"
[ 2 ]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea "GetUserNameA"
[ 3 ]: https://github.com/libecc/libecc/blob/master/src/curves/curves.c#L82 "ec_get_curve_params_by_type"
[ 4 ]: https://github.com/libecc/libecc/blob/master/include/libecc/lib_ecc_types.h#L159
[ 5 ]: https://neuromancer.sk/std/secg/secp256r1
[ 6 ]: https://github.com/libecc/libecc/blob/6167c16eb9846b26a819f70295c59362837b0c6c/src/external_deps/rand.c#L86
[ 7 ]: https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
[ 8 ]: https://github.com/kokke/tiny-AES-c
[ 9 ]: https://github.com/libecc/libecc/blob/6167c16eb9846b26a819f70295c59362837b0c6c/include/libecc/curves/ec_params.h#L51

# Solution

## Finding the vulnerability

This is where it should click for more experienced players:

***The plaintext hash is used as the nonce to sign the data and some of its bits are also appended in the file extension.***

In other words, probably due to lack of cryptology knowledge, the ransomware authors made their ransomware useless. We know that leaking a few bits of the nonce does almost always guarantee that the private key can be recovered with lattice reduction techniques. Of course, this assumes that we have access to several samples which in our case are $18$ in total.

The total leakage of each nonce (in bits) is:

$$5 \cdot 8 = 40\ \text{bits}$$

out of the total $256$ bits; that is $\sim 15\%$​ of the total bits.

First, let us write a python script to read the signatures as well as leaked bits from the file extensions.

```python
REPO_PATH = '...'

LEAKS = []
R = []
S = []

for root, dirs, files in os.walk(REPO_PATH):
    for f in files:
        sig = open(f'{root}/{f}', 'rb').read()[:0x40]
        R.append(int(sig[0x00:0x20].hex(), 16))
        S.append(int(sig[0x20:0x40].hex(), 16))
        LEAKS.append(int(f.split('.vlny')[1], 16))

SAMPLES = len(LEAKS)
```

Then, we need a way to express the unknown bits of the nonce $k$. For each nonce $k_i$, it holds that:

$$k_i = 2^{40} \cdot A_i + L_i$$

where:

- $A_i$ : the $256 - 40 = 216$ unknown bits of the nonce
- $L_i$ : the $40$ leaked bits of the nonce

By rearranging the $s$ component of the signature scheme, we see that each nonce can be written as:

$$xs_i = k_i - r_i \pmod q\\
k_i - xs_i - r_i = 0 \pmod q\\
2^{40} \cdot A_i + L_i - xs_i - r_i = 0 \pmod q\\
A_i - x (2^{-40}s_i) + 2^{-40}(L_i - r_i) = 0 \pmod q$$

which is exactly an instance of the Hidden Number Problem (HNP):

$$β_i -t_i \alpha + a_i = 0 \pmod p$$

where:

- $β_i = A_i$
- $t_i = 2^{-40}s_i$
- $\alpha = x$
- $a_i = 2^{-40}(L_i - r_i)$

Then, we can construct the following lattice:

$$\begin{bmatrix}\dfrac{q}{2^{216}} & \cdots & 0 \\\ \vdots & \ddots & \vdots \\\ 0 & \cdots & \dfrac{q}{2^{216}} \\\ \dfrac{2^{-40}}{2^{216}}s_0 & \cdots & \dfrac{2^{-40}}{2^{216}}s_{n-1} \\\ \dfrac{2^{-40}}{2^{216}}(r_0 - L_0) & \cdots & \dfrac{2^{-40}}{2^{216}}(r_{n-1} - L_{n-1})\end{bmatrix}$$

That is because the following holds:

$$l_0
\begin{pmatrix}
\frac{q}{2^{216}} \\ \vdots \\ 0
\end{pmatrix}
+
\cdots
+
l_{n-1}
\begin{pmatrix}
0 \\ \vdots \\ \frac{q}{2^{216}}
\end{pmatrix}
+
x
\begin{pmatrix}
\frac{2^{-40}}{2^{216}}s_0 \\ \vdots \\ \frac{2^{-40}}{2^{216}}s_{n-1}
\end{pmatrix}
+
\begin{pmatrix}
\frac{2^{-40}}{2^{216}}(r_0 - L_0) \\ \vdots \\ \frac{2^{-40}}{2^{216}}(r_{n-1} - L_{n-1})
\end{pmatrix}
=
\begin{pmatrix}
\frac{A_0}{2^{216}} \\ \vdots \\ \frac{A_{n-1}}{2^{216}}
\end{pmatrix}$$

We can construct this lattice with SageMath as follows:

```python
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
F = GF(n)

LS = 16**10
B = next_prime(n)
kW = next_prime(2**n.bit_length() // LS)
FLS = F(LS)

M = block_matrix(QQ, [
    [n / kW,],
    [(matrix(S) * FLS**(-1)) / kW,],
    [((matrix(R) - matrix(LEAKS)) * FLS**(-1)) / kW,],
])
```

Running LLL on this lattice, we expect the shortest vector to be our target one, containing $A_i$.

```python
for row in M.LLL():
    if row[0] != 0:
        k0 = LS * int(abs(row[0]*kW)) + LEAKS[0]
        x = pow(S[0], -1, n) * (k0 - R[0]) % n
        break
```

Having the private key, we can read the flag from the directory `crypto/curveware` inside the repository and decrypt it with AES in CBC mode. Note that the flag is also contained in the README.md in the root directory of the repository folder.

```python
x = x.to_bytes(32, 'big')

from Crypto.Cipher import AES

data = open(glob.glob(f"{REPO_PATH}/crypto/curveware/flag.txt*")[0], 'rb').read()

enc_flag = data[0x40:-0x10]
iv = data[-0x10:]

cipher = AES.new(x, AES.MODE_CBC, iv)

from Crypto.Util.Padding import unpad
print(unpad(cipher.decrypt(enc_flag), 16).decode())
```



## Getting the flag

A final summary of all that was said above:

1. Extensively read the ransomware's source code to figure out how the encryption and signature scheme works.
2. Find out that the same key is used for aes encryption and for data signing.
3. Translate the decompiled code into mathematical relations.
4. Notice that the appended hex extension leaks a few bits of the nonce which turns out to be enough to recover the private key using LLL.
