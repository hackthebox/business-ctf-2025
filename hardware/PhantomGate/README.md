![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>PhantomGate</font>

26<sup>th</sup> Mar 2025

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='red'>hard</font>

<br><br>

# Synopsis

- Firmware update (fwup) reverse engineering.
- Mounting rootfs of type ext2.
- Reverse engineering an ARM binary and a bash script.
- CryptAnalysis.
- Scripting a way to get the key.
- Scripting the decryption.

## Description

- At the heart of Volnaya’s cyber arsenal lies PhantomGate, a state-controlled technology company specializing in next-generation firewalls and network security appliances. These firewalls, deployed exclusively within Volnaya’s government and military networks, serve as the backbone of their cyber defenses, making any direct intrusion nearly impossible. However, intelligence operatives have successfully obtained two versions of PhantomGate’s firmware—an older, decrypted version and a newer, encrypted update. Your mission is to analyze the decrypted firmware, uncover how the upgrade process works, and develop a method to decrypt the latest encrypted firmware for further investigation.

## Skills Required

- A good knowledge of reverse engineering methods and tools.
- A good knowledge of symmitric encryption vulnerabilities.
- A good knowledge of one of the scripting languages.

# Solution

## Step 1: Reconnaissance

We begin with the provided `firmwares.tar` archive. Extracting this file reveals two firmware images:

```bash
$ ls
VN-PhantomGate-v4-VOL12LMNKS25-2025  VN-PhantomGate-v6-VOL12LMNOW25-2025.enc  firmwares.tar
```

## Step 2: Analyzing the plaintext firmware

First, we examine the unencrypted firmware file to understand its structure:

```bash
$ file VN-PhantomGate-v4-VOL12LMNKS25-2025
VN-PhantomGate-v4-VOL12LMNKS25-2025: Zip archive data, at least v2.0 to extract, compression method=deflate
```

The file is identified as a ZIP archive. Let's extract its contents:

```bash
$ unzip VN-PhantomGate-v4-VOL12LMNKS25-2025
Archive:  VN-PhantomGate-v4-VOL12LMNKS25-2025
  inflating: VN-PhantomGate-v4-VOL12LMNKS25-2025-meta.conf
   creating: data/
  inflating: data/rootfs.ext2
  inflating: data/zImage
  inflating: data/versatile-pb.dtb
```

The extracted files suggest this is a fwup firmware update package, containing:

- A configuration file (-meta.conf)
- A root filesystem image (rootfs.ext2)
- A Linux kernel image (zImage)
- A device tree blob (versatile-pb.dtb)

### Examining the Metadata Configuration

The -meta.conf file contains important information about the firmware components:

```text
meta-product="VN-PhantomGate-v4-VOL12LMNKS25-2025"
meta-version="v4.0"
meta-platform="versatilepb"
file-resource "rootfs.ext2" {
length=20971520
blake2b-256="ad8da8cf5f56ffdad2fbde20a4b3b6b29e927a7097e143ae055cb747ad48b250"
}
file-resource "zImage" {
length=3418912
blake2b-256="1a785b19c6e9baaab7a492ff9b60b3b8cff1870d419d4f3d8691e8d02ff06fbe"
}
file-resource "versatile-pb.dtb" {
length=9080
blake2b-256="a800c6b106a23b811873d4a934b6d29c1a68772037606d7c7bc0bc256964e064"
}
task "complete" {
on-resource "rootfs.ext2" {
funlist={"2","raw_write","0"}
}
on-resource "zImage" {
funlist={"2","raw_write","40960"}
}
on-resource "versatile-pb.dtb" {
funlist={"2","raw_write","51200"}
}
}
```

The firmware follows a consistent naming convention where the configuration file is named using the pattern `{firmware_name}-meta.conf`. This is evident both in the extracted files and in the ZIP archive structure.

Examining the raw header of the firmware file reveals important structural information:

```bash
xxd -l 100 VN-PhantomGate-v4-VOL12LMNKS25-2025
00000000: 504b 0304 1400 0000 0800 445e 795a 72f5  PK........D^yZr.
00000010: 44b7 6f01 0000 ab02 0000 2d00 1c00 564e  D.o.......-...VN
00000020: 2d50 6861 6e74 6f6d 4761 7465 2d76 342d  -PhantomGate-v4-
00000030: 564f 4c31 324c 4d4e 4b53 3235 2d32 3032  VOL12LMNKS25-202
00000040: 352d 6d65 7461 2e63 6f6e 6655 5409 0003  5-meta.confUT...
00000050: 406e e267 406e e267 7578 0b00 0104 0000  @n.g@n.gux......
00000060: 0000 0400                                ....
```

The consistent naming pattern ({firmware_name}-meta.conf) suggests this may be part of an automated build process, which could be valuable information when understanding the update mechanism.

## Step 3: Mounting the file system:

To examine the contents of the embedded Linux system, we'll mount the `rootfs.ext2` filesystem image. This ext2 filesystem contains the complete root directory structure of the target device.

### Preparing the Mount Environment

First, we create a dedicated mount point to maintain filesystem isolation:

```bash
mkdir rootfs
```

### Mounting the Filesystem

We use the mount command with loop device support to access the filesystem image:

```bash
sudo mount -o loop data/rootfs.ext2 rootfs/
```

- loop: Treats the file as a block device

## Step 4: Filesystem Reconnaissance and Firmware Update Mechanism Analysis

### Filesystem Structure Examination

Using the `tree` command provides a hierarchical overview of the filesystem structure, revealing critical components in the `/opt` directory:

```bash
$ tree opt/
opt/
├── fw_update_handler
└── update_fw.sh

1 directory, 2 files
```

The presence of these files suggests an automated firmware update mechanism, which warrants deeper investigation.

### Firmware Update Script Analysis

```bash
$ cat update_fw.sh
#!/bin/bash

# Firmware updating

# Configuration
UPDATE_CHECKER="/opt/fw_update_handler"
FWUP_CMD="fwup"                     # Firmware update tool
FIRMWARE_DIR="/opt/firmwares"       # Destination directory
LOG_FILE="/var/log/firmware_update.log"

# Function to extract version from hostname
get_firmware_version() {
    local hostname=$(hostname)
    # Extract version part (between 2nd and 3rd dash)
    local version=$(echo "$hostname" | cut -d'-' -f3)
    # Remove any trailing date (last dash and after)
    version=$(echo "$version" | sed 's/-[^-]*$//')
    echo "$version"
}

# Ensure required commands exist
for cmd in "$UPDATE_CHECKER" "$FWUP_CMD"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd not found" | tee -a "$LOG_FILE"
        exit 1
    fi
done

# Create firmware directory if it doesn't exist
mkdir -p "$FIRMWARE_DIR" || {
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$timestamp - Failed to create firmware directory" | tee -a "$LOG_FILE"
    exit 1
}

timestamp=$(date "+%Y-%m-%d %H:%M:%S")
current_version=$(get_firmware_version)

if [ -z "$current_version" ]; then
    echo "$timestamp - Error: Could not determine current version from hostname" | tee -a "$LOG_FILE"
    exit 1
fi

echo "$timestamp - Current firmware version: $current_version" | tee -a "$LOG_FILE"
echo "$timestamp - Checking for updates..." | tee -a "$LOG_FILE"

# Run the update checker
new_firmware=$("$UPDATE_CHECKER" "$current_version")
result=$?

if [ $result -ne 0 ]; then
    echo "$timestamp - Update check failed with error $result" | tee -a "$LOG_FILE"
    exit 1
fi

if [ -z "$new_firmware" ]; then
    echo "$timestamp - No updates available" | tee -a "$LOG_FILE"
    exit 0
fi

# Verify the downloaded firmware exists
if [ ! -f "$new_firmware" ]; then
    echo "$timestamp - Downloaded firmware not found: $new_firmware" | tee -a "$LOG_FILE"
    exit 1
fi

echo "$timestamp - New firmware downloaded: $new_firmware" | tee -a "$LOG_FILE"

# Apply the firmware update
echo "$timestamp - Applying firmware update..." | tee -a "$LOG_FILE"
if ! "$FWUP_CMD" -a -d /dev/mmcblk0 "$new_firmware"; then
    echo "$timestamp - Firmware update failed!" | tee -a "$LOG_FILE"
    exit 1
fi

# Move firmware to archive directory with version in filename
new_filename="firmware_${current_version}_$(date +%Y%m%d).fw"
destination="$FIRMWARE_DIR/$new_filename"

if ! mv "$new_firmware" "$destination"; then
    echo "$timestamp - Failed to move firmware to $FIRMWARE_DIR" | tee -a "$LOG_FILE"
    exit 1
fi

echo "$timestamp - Firmware update successful. Moved to $destination" | tee -a "$LOG_FILE"

new_hostname="VN-PhantomGate-$(echo "$new_firmware" | sed 's/\.enc$//')-$(date +%Y)"
hostnamectl set-hostname "$new_hostname"
echo "$timestamp - Updated hostname to $new_hostname" | tee -a "$LOG_FILE"

exit 0

```

The `update_fw.sh` script automates the firmware update process through the following logical flow:

### 1. Initialization Phase

- Sets essential paths and variables:
  - `UPDATE_CHECKER`: Binary that handles update availability checks
  - `FWUP_CMD`: Firmware update utility (`fwup`)
  - `FIRMWARE_DIR`: Storage location for firmware archives
  - `LOG_FILE`: Path for operation logging

### 2. Version Detection

- Uses a dedicated function `get_firmware_version()` that:
  1. Reads the current hostname
  2. Extracts the version component (third field when split by hyphens)
  3. Removes any trailing metadata after the version
- Example: From "VN-PhantomGate-v4-VOL12LMNKS25-2025" extracts "v4"

### 3. Pre-Update Checks

- Verifies the existence of required binaries:
  - The update checker (`/opt/fw_update_handler`)
  - The firmware utility (`fwup`)
- Creates the firmware directory if it doesn't exist

### 4. Update Check

- Executes the update checker binary with the current version as argument
- Receives either:
  - Path to a new firmware file (if update available)
  - Empty response (if no updates)

### 5. Update Execution

When new firmware is available:

1. Verifies the firmware file exists
2. Applies the update using:
   ```bash
   fwup -a -d /dev/mmcblk0 firmware_file
   ```

There is nothing here about the decryption process, we will have to check the binary.

## Step 5: Binary Analysis of fw_update_handler

### Initial Binary Inspection

The firmware update handler is a stripped compiled ARM executable:

```bash
$ file fw_update_handler
fw_update_handler: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 6.12.0, stripped
```

### String Analysis

The binary contains revealed several interesting strings when analyzed with strings

```text
http://xx.xx.xx.xx/phantom-gate/version?v=%s
http://xx.xx.xx.xx/phantom-gate/update?v=%s
Failed to create update file
/mnt/sdcard/phantom-gate-secret-key
Decryption successful. Output written to %s
```

### Reverse engineering with Ghidra

### Initial Static Analysis with Ghidra

After loading the stripped ARM binary into Ghidra, we focused on the main update routine. Through careful analysis of cross-references and string usage, we reconstructed and renamed several key functions and variables to improve readability.

```c

bool FUN_00011a04(int param_1,undefined4 *param_2)

{
  char *__s;
  char *__s1;
  int iVar1;
  FILE *pFVar2;
  size_t __size;
  void *__ptr;
  size_t sVar3;
  void *__ptr_00;
  bool bVar4;
  char acStack_214 [255];
  undefined local_115;
  undefined auStack_114 [256];
  int local_14;

  local_14 = __stack_chk_guard;
  if (param_1 != 2) {
    fprintf(stderr,"Usage: %s <current_version>\n",*param_2);
    bVar4 = true;
    goto LAB_00011dd8;
  }
  curl_global_init(3);
  __s = (char *)FUN_000111d8(param_2[1]);
  if (__s != (char *)0x0) {
    printf("Successfully downloaded version: %s\n",__s);
    __s1 = strrchr(__s,0x2e);
    if ((__s1 == (char *)0x0) || (iVar1 = strcmp(__s1,".enc"), iVar1 != 0)) {
      strncpy(acStack_214,__s,0xff);
      local_115 = 0;
    }
    else {
      strncpy(acStack_214,__s,(int)__s1 - (int)__s);
      __s1[(int)(acStack_214 + -(int)__s)] = '\0';
    }
    iVar1 = FUN_0001190c(auStack_114,0x100);
    if (iVar1 < 1) {
      fprintf(stderr,"Failed to read encryption key from %s\n","/mnt/sdcard/phantom-gate-secret-key"
             );
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    printf("Using key from %s (length: %d)\n","/mnt/sdcard/phantom-gate-secret-key",iVar1);
    pFVar2 = fopen(__s,"rb");
    if (pFVar2 == (FILE *)0x0) {
      perror("Failed to open input file");
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    fseek(pFVar2,0,2);
    __size = ftell(pFVar2);
    fseek(pFVar2,0,0);
    __ptr = malloc(__size);
    if (__ptr == (void *)0x0) {
      perror("Memory allocation failed");
      fclose(pFVar2);
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    sVar3 = fread(__ptr,1,__size,pFVar2);
    if (__size != sVar3) {
      perror("Failed to read input file");
      fclose(pFVar2);
      free(__ptr);
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    fclose(pFVar2);
    __ptr_00 = (void *)FUN_00011750(__ptr,__size,auStack_114,iVar1);
    if (__ptr_00 == (void *)0x0) {
      free(__ptr);
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    pFVar2 = fopen(acStack_214,"wb");
    if (pFVar2 == (FILE *)0x0) {
      perror("Failed to open output file");
      free(__ptr);
      free(__ptr_00);
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    fwrite(__ptr_00,1,__size,pFVar2);
    fclose(pFVar2);
    free(__ptr);
    free(__ptr_00);
    free(__s);
    printf("Decryption successful. Output written to %s\n",acStack_214);
  }
  curl_global_cleanup();
  bVar4 = __s == (char *)0x0;
LAB_00011dd8:
  if (local_14 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return bVar4;
}

```

Let's walk through this function step by step to understand how it processes firmware updates:

The program begins by validating the input arguments:

```c
if (param_1 != 2) {
    fprintf(stderr,"Usage: %s <current_version>\n",*param_2);
    bVar4 = true;
    goto LAB_00011dd8;
}
```

Initializes the CURL library with default settings (flag value 3), prepares for HTTP network operations.

```c
curl_global_init(3);
```

After that, a function is called with `param2[1]` as an argument, which corresponds to the version provided via the command line.

```c
__s = (char *)FUN_000111d8(param_2[1]);
```

Let's analyze what this function does.

```c
char * FUN_000111d8(undefined4 param_1)

{
  FILE *pFVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  int local_35c;
  char *local_358;
  int local_354;
  undefined4 local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined4 local_344;
  int local_340;
  undefined4 local_33c;
  char *local_338;
  FILE *local_334;
  undefined4 local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined4 local_324;
  long local_320;
  char *local_31c [2];
  char acStack_314 [256];
  char acStack_214 [256];
  char acStack_114 [256];
  int local_14;

  local_14 = __stack_chk_guard;
  FUN_0001101c(local_31c);
  local_358 = (char *)0x0;
  snprintf(acStack_314,0x100,"http://xx.xx.xx.xx/phantom-gate/version?v=%s",param_1);
  local_354 = curl_easy_init();
  if (local_354 == 0) {
    fwrite("curl_easy_init() failed\n",1,0x18,stderr);
    free(local_31c[0]);
    pcVar4 = (char *)0x0;
  }
  else {
    local_350 = 0x2712;
    curl_easy_setopt(local_354,0x2712,acStack_314);
    local_34c = 0x4e2b;
    curl_easy_setopt(local_354,0x4e2b,FUN_000110c4);
    local_348 = 0x2711;
    curl_easy_setopt(local_354,0x2711,local_31c);
    local_344 = 0x2722;
    curl_easy_setopt(local_354,0x2722,"libcurl-agent/1.0");
    local_340 = curl_easy_perform(local_354);
    pFVar1 = stderr;
    if (local_340 == 0) {
      local_35c = 0;
      local_33c = 0x200002;
      curl_easy_getinfo(local_354,0x200002,&local_35c);
      curl_easy_cleanup(local_354);
      if (local_35c == 200) {
        printf("Server response: %s\n",local_31c[0]);
        iVar3 = strcmp(local_31c[0],"no update");
        if (iVar3 == 0) {
          puts("No updates available");
        }
        else {
          local_338 = local_31c[0] + 7;
          local_358 = strndup(local_338,0x32);
          printf("New version available: %s\n",local_358);
          snprintf(acStack_214,0x100,"http://xx.xx.xx.xx/phantom-gate/update?v=%s",local_358);
          snprintf(acStack_114,0x100,"%s.enc",local_358);
          local_334 = fopen(acStack_114,"wb");
          if (local_334 == (FILE *)0x0) {
            fwrite("Failed to create update file\n",1,0x1d,stderr);
            free(local_358);
            free(local_31c[0]);
            pcVar4 = (char *)0x0;
            goto LAB_000116ac;
          }
          local_354 = curl_easy_init();
          if (local_354 == 0) {
            fclose(local_334);
            remove(acStack_114);
            free(local_358);
            local_358 = (char *)0x0;
          }
          else {
            local_330 = 0x2712;
            curl_easy_setopt(local_354,0x2712,acStack_214);
            local_32c = 0x4e2b;
            curl_easy_setopt(local_354,0x4e2b,fwrite);
            local_328 = 0x2711;
            curl_easy_setopt(local_354,0x2711,local_334);
            local_324 = 0x2d;
            curl_easy_setopt(local_354,0x2d,1);
            local_340 = curl_easy_perform(local_354);
            pFVar1 = stderr;
            if (local_340 == 0) {
              local_320 = ftell(local_334);
              fclose(local_334);
              if (local_320 < 1) {
                fwrite("Downloaded file is empty\n",1,0x19,stderr);
                remove(acStack_114);
                free(local_358);
                local_358 = (char *)0x0;
              }
              else {
                printf("Successfully downloaded %ld bytes to %s\n",local_320,acStack_114);
                free(local_358);
                local_358 = strdup(acStack_114);
              }
            }
            else {
              uVar2 = curl_easy_strerror(local_340);
              fprintf(pFVar1,"Download failed: %s\n",uVar2);
              fclose(local_334);
              remove(acStack_114);
              free(local_358);
              local_358 = (char *)0x0;
            }
            curl_easy_cleanup(local_354);
          }
        }
        free(local_31c[0]);
        pcVar4 = local_358;
      }
      else {
        fprintf(stderr,"HTTP request failed with code %ld\n",local_35c);
        free(local_31c[0]);
        pcVar4 = (char *)0x0;
      }
    }
    else {
      uVar2 = curl_easy_strerror(local_340);
      fprintf(pFVar1,"curl_easy_perform() failed: %s\n",uVar2);
      curl_easy_cleanup(local_354);
      free(local_31c[0]);
      pcVar4 = (char *)0x0;
    }
  }
LAB_000116ac:
  if (local_14 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return pcVar4;
}
```

This function manages the entire version check and download workflow. If a downloaded version exists, it returns it—but there’s no indication of any decryption process.

The next interesting part is:

```c
    iVar1 = FUN_0001190c(auStack_114,0x100);
    if (iVar1 < 1) {
      fprintf(stderr,"Failed to read encryption key from %s\n","/mnt/sdcard/phantom-gate-secret-key"
             );
      free(__s);
      bVar4 = true;
      goto LAB_00011dd8;
    }
    printf("Using key from %s (length: %d)\n","/mnt/sdcard/phantom-gate-secret-key",iVar1);
```

If we analyze `FUN_0001190c()`, we see the following implementation:

```c
size_t FUN_0001190c(char *param_1,int param_2)

{
  int __fd;
  ssize_t sVar1;
  char *pcVar2;
  size_t sVar3;

  __fd = open("/mnt/sdcard/phantom-gate-secret-key",0);
  if (__fd < 0) {
    perror("Failed to open key file");
    sVar3 = 0xffffffff;
  }
  else {
    sVar1 = read(__fd,param_1,param_2 - 1);
    close(__fd);
    if (sVar1 < 1) {
      perror("Failed to read key");
      sVar3 = 0xffffffff;
    }
    else {
      param_1[sVar1] = '\0';
      pcVar2 = strchr(param_1,10);
      if (pcVar2 != (char *)0x0) {
        *pcVar2 = '\0';
      }
      sVar3 = strlen(param_1);
    }
  }
  return sVar3;
}
```

This function attempts to read a file `/mnt/sdcard/phantom-gate-secret-key`. Given its name, it’s evident that this file contains the encryption key used for the firmware.
It stores the key in param1 and returns its length.

Back in the main function, the key is stored in `auStack_114`, so we can rename it to key for clarity.

Next, the function opens the input file and determines its size.

```c
    pFVar1 = fopen(__s,"rb");
    if (pFVar1 == (FILE *)0x0) {
      perror("Failed to open input file");
      free(__s);
      bVar3 = true;
      goto LAB_00011dd8;
    }
    fseek(pFVar1,0,2);
    __size = ftell(pFVar1);
    fseek(pFVar1,0,0);
    __ptr = malloc(__size);
    if (__ptr == (void *)0x0) {
      perror("Memory allocation failed");
      fclose(pFVar1);
      free(__s);
      bVar3 = true;
      goto LAB_00011dd8;
    }
    sVar2 = fread(__ptr,1,__size,pFVar1);
    if (__size != sVar2) {
      perror("Failed to read input file");
      fclose(pFVar1);
      free(__ptr);
      free(__s);
      bVar3 = true;
      goto LAB_00011dd8;
    }
    fclose(pFVar1);
```

Now, here’s an interesting line:

```c
__ptr_00 = (void *)FUN_00011750(__ptr,__size,key,key_len);
```

This function takes the input file’s data, its size, the encryption key, and the key length. Given these parameters, it strongly suggests that this is the decryption function.

```c
void * FUN_00011750(int param_1,size_t param_2,int param_3,undefined4 param_4)

{
  byte bVar1;
  void *pvVar2;
  int extraout_r1;
  uint uVar3;
  byte local_27;
  uint local_24;
  int local_20;
  int local_1c;

  pvVar2 = malloc(param_2);
  if (pvVar2 == (void *)0x0) {
    fwrite("Memory allocation failed\n",1,0x19,stderr);
    pvVar2 = (void *)0x0;
  }
  else {
    local_24 = 0;
    local_27 = 0xff;
    do {
      local_20 = 0;
      local_1c = 0;
      while (local_20 != 0x200) {
        uVar3 = local_24 + local_20;
        if (param_2 <= uVar3) {
          return pvVar2;
        }
        bVar1 = *(byte *)(param_1 + uVar3);
        *(byte *)((int)pvVar2 + uVar3) =
             (*(byte *)(param_3 + local_1c) ^ bVar1 ^ local_27) - (char)local_1c;
        FUN_00012044(local_1c + 1,param_4);
        local_20 = local_20 + 1;
        local_27 = bVar1;
        if (local_20 == 0x200) break;
        local_1c = extraout_r1;
        if (param_2 < local_24 + local_20) {
          return pvVar2;
        }
      }
      local_24 = local_24 + 0x200;
    } while (local_24 < param_2);
  }
  return pvVar2;
}
```

First it's allocate a memory that match input size

```c
pvVar2 = malloc(param_2);
if (pvVar2 == (void *)0x0) {
    fwrite("Memory allocation failed\n",1,0x19,stderr);
    pvVar2 = (void *)0x0;
}
```

### Decryption Algorithm

The core decryption process uses a block-based XOR cipher with transformations:
c
Copy

```c
_(byte _)((int)pvVar2 + uVar3) =
(_(byte _)(param_3 + local_1c) ^ bVar1 ^ local_27) - (char)local_1c;
```

Decryption Steps:

- Processes data in 512-byte blocks (0x200)
- For each byte:

  - XORs with key byte: key[local_1c]
  - XORs with previous ciphertext byte (local_27)
  - Subtracts current position counter (local_1c)

- Maintains state between blocks via local_27 (last processed byte)

Here is the control flow

```c
do {
    local_20 = 0;  // Block position counter
    while (local_20 != 0x200) {  // Process 512-byte blocks
        // ... decryption logic ...
        local_20 = local_20 + 1;
        local_27 = bVar1;  // Store last byte for next iteration
    }
    local_24 = local_24 + 0x200;  // Move to next block
} while (local_24 < param_2);  // Until all data processed
```

Key Characteristics

- Custom XOR-based stream cipher
- Block processing (512-byte chunks)
- Uses previous byte feedback (local_27)

To demonstrate our comprehension of the custom encryption algorithm, we've implemented both the encryption and decryption processes in Python.

```python
def encrypt(cleartext: bytes, key: bytes) -> bytes:
    num_bytes = len(cleartext)
    key_len = len(key)
    ciphertext = bytearray(num_bytes)

    ptr = 0
    previous_ciphertext_byte = 0xFF

    while True:
        block_offset = 0
        key_offset = 0

        while block_offset != 0x200:
            offs = ptr + block_offset
            if offs >= num_bytes:
                return bytes(ciphertext)

            cleartext_byte = (cleartext[offs] + key_offset) & 0xFF
            xor = (previous_ciphertext_byte ^ cleartext_byte ^ key[key_offset]) & 0xFF

            ciphertext[offs] = xor
            previous_ciphertext_byte = xor
            key_offset = (key_offset + 1) % key_len
            block_offset += 1

            if block_offset == 0x200:
                break

            if ptr + block_offset > num_bytes:
                return bytes(ciphertext)

        ptr += 0x200
        if ptr >= num_bytes:
            return bytes(ciphertext)

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    num_bytes = len(ciphertext)
    key_len = len(key)
    cleartext = bytearray(num_bytes)

    ptr = 0
    previous_ciphertext_byte = 0xFF

    while True:
        block_offset = 0
        key_offset = 0

        while block_offset != 0x200:
            offs = ptr + block_offset
            if offs >= num_bytes:
                return bytes(cleartext)

            ciphertext_byte = ciphertext[offs]
            xor = (previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]) & 0xFF

            cleartext[offs] = (xor - key_offset) & 0xFF
            previous_ciphertext_byte = ciphertext_byte
            key_offset = (key_offset + 1) % key_len
            block_offset += 1

            if ptr + block_offset > num_bytes:
                return bytes(cleartext)

        ptr += 0x200
        if ptr >= num_bytes:
            return bytes(cleartext)

```

We then wrote some scaffolding to test the functions using an arbitrary 32-byte key, and confirmed that they successfully encrypted and decrypted a test string (validating our understanding of the mathematical operations):

```bash
Key: XG8Y72LNP45KOMRZ3Q9B6DMEF7TVOEYA
Plain text: The quick brown fox jumps over the lazy dog.
Encrypted: b'\xf3\xdd\x82\xf8\xba\xf2\xd1\xf5\xd6\xcb\x92\xa4\x90Yw\x02G\x96%T\x1c\xd2\x1c\xde\x13\x1d\xc0\x07\xc9\x03d\xb6\x86\xa7\xbd\x8b\xd9\x94\xa7\xce\xf2\xbe\xfa\x88'
Decrypted: b'The quick brown fox jumps over the lazy dog.'
```

At that point, we believed we had successfully reproduced the cryptographic algorithm used to decrypt PhantomGate firmware images, but of course we could not confirm that without a valid key. Our reverse engineering effort had not revealed hard-coded decryption keys within the `fw_update_handler` binary nor anywhere else on the system.

To obtain decryption keys, then, we needed to analyze the cryptographic scheme for weaknesses that might allow us to derive them.

## Step 6: Cryptanalysis

Looking over the structure of the encrypt function above, we saw two nested while loops:

- The outer loop iterates through 512-byte blocks of data and processes them separately without passing any input from one to the next. This appears to be something basic like AES (Advanced Encryption Standard) using ECB (Electronic Code Book) mode.
- The inner loop iterates through the bytes within a block and processes each byte using a mathematical XOR operation that includes a key byte as well as the output from the operation on the previous byte. This looks like a basic stream cipher.

### Reviewing stream cipher security

In practice, a static key is typically used to seed an algorithm that generates a keystream, which is then combined with the cleartext using the XOR operation to produce the ciphertext.

This describes the inner loop of the PhantomGate encryption function reasonably well, with one crucial difference: the keystream in this cipher consists solely of the 32-byte key repeated 16 times. Similar to what we saw with the block cipher, repetition of the key can produce recognizable patterns in the ciphertext. Furthermore, because of the mathematical properties of the XOR operation, the repetition allows us to conduct a `known-plaintext` attack against any 32 bytes of the ciphertext and recover the key

```
A known-plaintext attack (KPA) is a cryptanalysis technique where an attacker has access to both plaintext and its corresponding ciphertext and uses this information to deduce the encryption key or recover additional encrypted messages.
```

As the following XOR operations are all true:

```
A ^ B = C
A ^ C = B
B ^ C = A
```

And if we substitute the variable letters with the components of our encryption cipher, it gets a little more interesting:

```
key ^ cleartext = ciphertext (encrypt)
key ^ ciphertext = cleartext (decrypt)
cleartext ^ ciphertext = key (recover)
```

Thus, if we know the cleartext and ciphertext, we can derive the key simply by feeding them into the encryption algorithm.

### Conducting pattern analysis

As we know, the `fwup` file is a ZIP archive, and its first two magic bytes are `PK`.

To test our attack, we can use the script we wrote earlier to generate encrypted versions of these two bytes:

```bash
Key: XG8Y72LNP45KOMRZ3Q9B6DMEF7TVOEYA
Plain text: PK
Encrypted: b'\xf7\xfc'
Decrypted: b'PK'
```

Additionally, we know that the key byte can be derived using the following formula: `prev_byte ^ cipher_byte ^ (plain_byte + key_offset) & 0xFF`

From the encryption code, we determine the initial values:

- prev_byte = 0xff (starting value)
- cipher_byte = 0xf7 (first encrypted byte)
- plain_byte = 'P' (ASCII value 80)
- key_offset = 0 (since this is the first character in the first 32-byte block)

Using these values, we compute the first key byte:

```python
>>> 0xff ^ 0xf7 ^ (ord('P') + 0) & 0xff
88
>>> chr(88)
'X'
>>>
```

As expected, we recover 'X', the first byte of our key. This confirms the validity of our attack and demonstrates how we can systematically extract the entire encryption key.

## Step 7: Extracting the Key

Now that we know a `known-plaintext` attack is possible, the next step is understanding how to execute it effectively.

During our initial analysis, we discovered that the ZIP archive contains a fwup configuration file named ({firmware_name}-meta.conf). This means that for the encrypted firmware, the corresponding configuration file will be:
`VN-PhantomGate-v6-VOL12LMNOW25-2025-meta.conf`

Additionally, from the plaintext firmware, we can determine that the configuration file name starts at index 30 within the archive. Examining the first 100 bytes with xxd confirms this:

```bash
$ xxd -l 100 VN-PhantomGate-v4-VOL12LMNKS25-2025
00000000: 504b 0304 1400 0000 0800 445e 795a 72f5  PK........D^yZr.
00000010: 44b7 6f01 0000 ab02 0000 2d00 1c00 564e  D.o.......-...VN
00000020: 2d50 6861 6e74 6f6d 4761 7465 2d76 342d  -PhantomGate-v4-
00000030: 564f 4c31 324c 4d4e 4b53 3235 2d32 3032  VOL12LMNKS25-202
00000040: 352d 6d65 7461 2e63 6f6e 6655 5409 0003  5-meta.confUT...
00000050: 406e e267 406e e267 7578 0b00 0104 0000  @n.g@n.gux......
00000060: 0000 0400                                ....
```

Since we know the encryption key is 32 bytes long, and the firmware name is sufficiently long, we can extract the key starting from index 32 (right after `VN`), without needing to account for the two preceding bytes.

This provides us with a reliable plaintext-ciphertext pair to systematically recover the encryption key.

### Writing the key extractor script

With all the information we've gathered so far, we're now ready to write a script to extract the encryption key.

```python
#!/usr/bin/python3

import sys
import os

KNOWN_TEXT_START_INDX = 32
KEY_LEN = 32

def recover_key_byte(cipher_byte, plain_byte, prev_byte, key_offset):
    return (prev_byte ^ cipher_byte ^ (plain_byte + key_offset)) & 0xFF

def extract_key(enc):
    base_filename = os.path.splitext(os.path.basename(enc))[0]
    conf_file = (base_filename + "-meta.conf")[2:]
    print(f"[+] Known bytes: {conf_file}")

    key = ""
    with open(enc, "rb") as f:
        encrypted_fw = f.read()
        for i in range(KEY_LEN):
            index = KNOWN_TEXT_START_INDX + i

            prev_byte = encrypted_fw[index - 1]
            cipher_byte = encrypted_fw[index]
            plain_byte = conf_file[i]
            key_offset = i

            key_byte = recover_key_byte(
                cipher_byte=cipher_byte,
                prev_byte=prev_byte,
                plain_byte=ord(plain_byte),
                key_offset=key_offset
            )
            key += chr(key_byte)
    return key


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python phantom_key_ext.py <encrypted_file>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    print(f"[+] Encrypted firmware: {encrypted_file}")

    key = extract_key(encrypted_file)

    print(f"[+] Key: {key}")
```

With our script ready, we can now run it on the encrypted firmware to extract the encryption key:

```bash
$ ./phantom_key_ext.py VN-PhantomGate-v6-VOL12LMNOW25-2025.enc
[+] Encrypted firmware: VN-PhantomGate-v6-VOL12LMNOW25-2025.enc
[+] Known bytes: -PhantomGate-v6-VOL12LMNOW25-2025-meta.conf
[+] Key: PGYF78GNG4OPL3N64P4O8N4EF6NOERG9
```

As expected, the script successfully extracts the 32-byte encryption key: `PGYF78GNG4OPL3N64P4O8N4EF6NOERG9`

## Step 8: Decrypting the firmware

After successfully obtaining the decryption key, it's time to verify whether we have the correct key. To do this, we'll use it to decrypt the firmware. However, before proceeding, we need to slightly modify the encryption script we wrote earlier to support file decryption.

```python
#!/usr/bin/python3

import sys

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cleartext = bytearray(len(ciphertext))
    ptr = 0
    previous_ciphertext_byte = 0xFF
    key_len = len(key)
    num_bytes = len(ciphertext)

    while True:
        block_offset = 0
        key_offset = 0

        while block_offset != 0x200:
            offs = ptr + block_offset
            if offs >= num_bytes:
                return bytes(cleartext)

            ciphertext_byte = ciphertext[offs]
            xor = previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]
            xor = (xor + 256) & 0xFF

            cleartext[offs] = (xor - key_offset) & 0xFF

            previous_ciphertext_byte = ciphertext_byte
            key_offset = (key_offset + 1) % key_len
            block_offset += 1

            if ptr + block_offset > num_bytes:
                return bytes(cleartext)

        ptr += 0x200
        if ptr >= num_bytes:
            return bytes(cleartext)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file> <key>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3].encode('utf-8')

    try:
        # Read the input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        # Decrypt the data
        cleartext = decrypt(ciphertext, key)

        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(cleartext)

        print(f"Decryption successful. Output written to {output_file}")

    except IOError as e:
        print(f"File error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

To decrypt the firmware, we execute the script as follows:

```bash
$ ./fw_dec.py VN-PhantomGate-v6-VOL12LMNOW25-2025.enc output_fw PGYF78GNG4OPL3N64P4O8N4EF6NOERG9
Decryption successful. Output written to output_fw
```

If the decryption is successful, `output_fw` should be recognized as a ZIP archive:

```bash
$ file output_fw
output_fw: Zip archive data, at least v2.0 to extract, compression method=deflate
```

We have now successfully decrypted the firmware.

## Step 9: Extract the flag

Now that we have successfully decrypted the firmware, it's time to analyze it and search for the flag.
First, we need to unzip the decrypted firmware archive:

```bash
$ unzip output_fw
Archive:  output_fw
  inflating: VN-PhantomGate-v6-VOL12LMNOW25-2025-meta.conf
   creating: data/
  inflating: data/rootfs.ext2
  inflating: data/zImage
  inflating: data/versatile-pb.dtb
```

Next, we mount the extracted filesystem to explore its contents:

```bash
$ mkdir filesys
$ sudo mount -o loop data/rootfs.ext2 filesys/
```

Once mounted, we can list the directory structure to verify:

```bash
ls filesys/
bin  crond.reboot  dev  etc  lib  lib32  linuxrc  lost+found  media  mnt  opt  proc  root  run  sbin  sys  tmp  usr  var
```

To locate the flag, we use the `find` command to search the filesystem for files matching the pattern flag\*:

```bash
$ sudo find filesys/ -iname flag*
filesys/root/flag.txt
```

Finally, we can read the flag file:

```bash
$ sudo cat filesys/root/flag.txt
HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
