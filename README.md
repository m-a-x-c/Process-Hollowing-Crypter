# 💣 Process Hollowing Crypter 💻

This GitHub repository hosts the **Process Hollowing Crypter** project, a tool developed in C, focused on the implementation of the process hollowing technique. The project is in active development, representing an exploration into cybersecurity, software engineering, low-level programming, and malware analysis.


## What is Process Hollowing?

Process hollowing is a stealth technique used by malware authors to inject malicious code into legitimate processes running on a system. This method allows the malware to execute under the guise of a trusted application, thereby evading detection from security software.

## 🎯 Project Objective

The goal of this project is to create a crypter using the process hollowing technique. This crypter will be capable of injecting a payload into a legitimate Windows process, allowing the payload to run undetected.

## 🚀 Features

- Process creation in a suspended state.
- Unmapping the primary module of the target process.
- Allocating memory within the target process for the payload.
- Injecting the payload into the target process.
- Resuming the target process to execute the payload.

## 🛠️ How It Works

1. **Create a Suspended Process:** The crypter starts by creating a legitimate process, such as notepad.exe, in a suspended state.
2. **Unmap the Primary Module:** It then unmaps the memory of the primary module of the suspended process.
3. **Load and Inject the Payload:** The crypter loads the payload from a specified file and injects it into the memory space vacated by the unmapped primary module.
4. **Resume Execution:** Finally, the crypter modifies the entry point of the suspended process to point to the injected payload and resumes the process.

## 🧰 Prerequisites

- Windows environment for development and testing.
- GCC for compiling the C code.
- Basic understanding of Windows API and C programming.

## 🛠️ Setup and Compilation

To compile the project, you will need GCC installed on your system. Use the following command to compile the code:

```bash
gcc crypter.c -o crypter.exe -lpsapi

