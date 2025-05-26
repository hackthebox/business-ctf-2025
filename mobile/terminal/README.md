# Terminal Challenge - Reverse Engineering

This challenge involves reverse engineering a terminal emulator that simulates a C2 (Command and Control) interface. The goal is to find the hidden flag by analyzing the application's code and functionality.

## Code Analysis

### Key Components

1. **C2 Mode Activation**
   - Located in `terminal_controller.dart`
   - Password is hardcoded: `c2Password = "w0w_y0u_f0und_m3"`
   - Activation check in `c2ModeCommand()` function

2. **Flag Encryption**
   - Located in `commands.dart`
   - Uses RC4 encryption (via PointyCastle library)
   - Base64 encoded secret: `3+3haP80SM7i/ijRRRlwt09zsPzc1o8tMQezph0Gm63nfkKl9GA=`
   - Encryption key is derived from the current path

3. **Decryption Process**
   ```dart
   Uint8List encryptedBytes = base64.decode(base64Secret);
   Uint8List keyBytes = Uint8List.fromList(utf8.encode(controller.currentPath));
   pc.StreamCipher cipher = pc.StreamCipher('RC4');
   cipher.init(false, pc.KeyParameter(keyBytes));
   Uint8List decryptedBytes = cipher.process(encryptedBytes);
   ```

## Solution Steps

1. **Code Analysis**
   - Examine `terminal_controller.dart` to find C2 mode password
   - Analyze `commands.dart` to understand flag encryption mechanism

2. **Exploitation**
   - Activate C2 mode using discovered password:
   ```
   c2-mode w0w_y0u_f0und_m3
   ```
   - Use `get-secret` command to trigger decryption:
   ```
   get-secret
   ```

## Technical Details

- **Encryption**: RC4 stream cipher
- **Key Derivation**: Current path is used as encryption key
- **Dependencies**:
  - `pointycastle: ^3.0.0` for RC4 implementation
  - `intl: ^0.19.0` for date formatting

## Available Commands

- `help` - Show available commands
- `ls [path]` - List directory contents
- `cd <directory>` - Change directory
- `echo <text>` - Display text
- `clear` - Clear the terminal screen
- `cat <file>` - Display file content
- `mkdir <directory>` - Create a new directory
- `touch <file>` - Create a new empty file
- `rm <file/dir>` - Remove a file or directory
- `date` - Show the curr`ent date and time
- `c2-mode <password>` - Activate C2 mode (requires password)
- `get-secret` - Display the secret message (C2 Mode only)
