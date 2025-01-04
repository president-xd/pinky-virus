# Pinky Virus
## Overview

This virus should be assembled with FASM x64 (tested with version 1.73.27 on Linux 5.11.14-gentoo). 
It relies on the Reverse Text Segment Infection technique where the segment is extended in reverse by PAGE_SIZE to make room for the virus. This technique only works on regular ELF executables (does not work with PIE). 
It is also not working on systems with huge pages enabled at this time. PAGE_SIZE alignment should be calculated dynamically, but this code assumes its value of 4096 for demonstration purposes. It infects the current directory (non-recursively). The entry point still resides in the .text segment, which is less suspicious.

## Installation:
1. First clone the repository
   ```bash
   git clone github.com/president-xd/pinky-virus
   ```
2. Change the directory to Repository
  ```bash
  cd pinky-virus
  ```
3. Place your ELF in the directory where ELF is located.
   ```bash
   cp /path/of/elf /path/to/pinky-virus
   ```
4. Compile the ASM file
   ```bash
   fasm pinky-virus
   ```
5. Add random bytes to positon after the magic bytes
   ```bash
   echo -n 544d5a00 | xxd -r -p -s pinky-virus
   ```
6. Execute the pinky-virus
   ```bash
   sudo chmod +x pinky-virus
   ./pinky-virus
   ```
7. Run your ELFs
   ```bash
    ./your-elfs-name
   ```

## Demo Installation
Here is the demo, that we used in the our system. We used automated injection using bash script to automate all commands. In this demo, we used sample files named file.c and file2.c. Here are codes and results:
1. Code of File.c
   ```c
    #include <stdio.h>

    int main(){
      printf("This is file.c file.");
      return 0;
    }
   ```
2. Code of File2.c named hi.c
      ```c
    #include <stdio.h>

    int main(){
      printf("Hello World!");
      return 0;
    }
   ```
**Note:** The pinky-virus file is available in the my github repo.
### Before Infection
![image](https://github.com/user-attachments/assets/2d97481f-1e84-4c18-b71a-7df4c48b64d4)

![image](https://github.com/user-attachments/assets/5c36f850-047a-4bae-8ba0-c87cbc5a098b)

![image](https://github.com/user-attachments/assets/8deedb17-ce36-45f3-a006-bf6e67432029)

### After Infection
![image](https://github.com/user-attachments/assets/4ebc7c81-a3c0-48d0-8db3-07563bc3de06)

![image](https://github.com/user-attachments/assets/b829f255-b589-45f7-a618-84b84a5f61cb)

![image](https://github.com/user-attachments/assets/1a94dc26-b921-47b8-83db-0d8dc1efcdde)

## Script that we used for automation
```bash
#!/bin/bash

# Define the file names to check and delete
files=("virus" "hi" "file")

# Delete specified files
echo "========================= CLEANING UP OLD FILES ========================="
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "Deleting $file..."
        rm "$file"
    else
        echo "$file not found, skipping..."
    fi
done
echo "======================================================================="
echo " "

# Compile the commands
echo "============================= COMPILATION ============================="
echo "1. Compiling file.c..."
gcc file.c -o file -no-pie && echo "file.c compiled successfully!" || echo "Failed to compile file.c."
echo "------------------------------------------------------------------------"

echo "2. Compiling hi.c..."
gcc hi.c -o hi -no-pie && echo "hi.c compiled successfully!" || echo "Failed to compile hi.c."
echo "------------------------------------------------------------------------"

echo "3. Assembling virus.asm..."
fasm virus.asm && echo "==>  Virus.asm assembled successfully!" || echo "Failed to assemble virus.asm."
echo "======================================================================="
echo " "

# Analyze ELF headers before injection
echo "========================= ELF HEADER ANALYSIS ========================="
if [ -f "hi" ]; then
    echo "----------------------------- hi.c ELF Header --------------------------"
    readelf -h hi
else
    echo "Error: hi executable not found!"
fi
echo "----------------------------------------------------------------------"
echo " "

if [ -f "file" ]; then
    echo "--------------------------- file.c ELF Header --------------------------"
    readelf -h file
else
    echo "Error: file executable not found!"
fi
echo "----------------------------------------------------------------------"
echo " "

# Execute ELF files before injection
echo "====================== EXECUTION BEFORE INJECTION ======================"
if [ -x "./hi" ]; then
    echo "----------------------------- Executing hi.c --------------------------"
    ./hi
else
    echo "Error: Unable to execute hi executable!"
fi
echo ""
echo "----------------------------------------------------------------------"
echo " "

if [ -x "./file" ]; then
    echo "--------------------------- Executing file.c --------------------------"
    ./file
else
    echo "Error: Unable to execute file executable!"
fi
echo ""
echo "----------------------------------------------------------------------"
echo " "

# Execute virus file
echo "========================= VIRUS EXECUTION ============================="
if [ -f "virus" ]; then
    echo "Executing virus..."
    chmod +x virus
    echo "------------------------------------------------------------------------"
    ./virus && echo "==>  Virus executed successfully!" || echo "Error executing virus file!"
    echo "------------------------------------------------------------------------"
else
    echo "Error: virus file not found!"
fi
echo "======================================================================="
echo " "

# Inject magic byte (for educational purposes only)
echo "========================= MAGIC BYTE INJECTION ========================="
if [ -f "virus" ]; then
    echo -n "544d5a00" | xxd -r -p > virus
    echo "Magic byte injection completed."
else
    echo "Error: virus file not found for injection!"
fi
echo "======================================================================="
echo " "

# Analyze ELF headers after injection
echo "====================== ELF HEADER AFTER INJECTION ======================"
if [ -f "file" ]; then
    echo "--------------------------- file.c ELF Header --------------------------"
    readelf -h file
else
    echo "Error: file executable not found!"
fi
echo "----------------------------------------------------------------------"
echo " "

if [ -f "hi" ]; then
    echo "----------------------------- hi.c ELF Header --------------------------"
    readelf -h hi
else
    echo "Error: hi executable not found!"
fi
echo "----------------------------------------------------------------------"
echo " "

# Execute ELF files after injection
echo "====================== EXECUTION AFTER INJECTION ======================="
if [ -x "./hi" ]; then
    echo "----------------------------- Executing hi.c --------------------------"
    ./hi
else
    echo "Error: Unable to execute hi executable!"
fi
echo "----------------------------------------------------------------------"
echo " "

if [ -x "./file" ]; then
    echo "--------------------------- Executing file.c --------------------------"
    ./file
else
    echo "Error: Unable to execute file executable!"
fi
echo ""
echo "----------------------------------------------------------------------"
echo " "

# End of script
echo "=============================== FINISHED =============================="
```

# x64 ELF Infector Using Reverse Text Segment Infection

## Infection Technique in Detail

### How It Works

1. **Reverse Text Segment Infection:**
   - The virus extends the text segment of the ELF file in reverse by a page size (typically 4096 bytes) to make room for its code.

2. **Limitations:**
   - This technique works only on regular ELF executables and does not work with Position-Independent Executables (PIE).
   - The virus does not operate on systems with huge pages enabled (pages larger than 4096 bytes).

3. **PAGE_SIZE Alignment:**
   - The alignment should be dynamically calculated, but for demonstration purposes, this code assumes a page size of 4096 bytes.

4. **Infection Process:**
   - It infects files in the current directory only (non-recursive).
   - It has no destructive payload, meaning it does not damage the files it infects.

5. **Entry Point:**
   - The virus's entry point remains in the text segment of the infected file, making it less suspicious and harder to detect.
  
### Visual Representation
![image](https://github.com/user-attachments/assets/5a8d3bfe-92dc-4014-a4b9-edc82caa1429)


### Technical Details

#### Virus Type
- x64 ELF infector

#### Technique
- Reverse Text Segment Infection

#### Infection Scope
- Infects files in the current directory (non-recursive)

#### Payload
- Non-destructive (It can be destructive if any individual binds malware such as reverse shell, or ransomware etc.)

#### Limitations
- Does not work with PIE executables
- Incompatible with systems using huge pages
- Assumes PAGE_SIZE is 4096 bytes

#### Entry Point
- Remains within the text segment, making it less suspicious

## Notes
- This explanation assumes a PAGE_SIZE of 4096 for simplicity and demonstration purposes.
- Use it for educational purposes only.

### Shout-Out
- A big thanks for those who keeps the VX scene alive!
- @guitmz || @TMZvx

### Contributors
- Abdul Wahab Khan
- Asad Muhammad Channer
- Qazi Muhammad Awais
