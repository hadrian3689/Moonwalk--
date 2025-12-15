# Moonwalk++ 

PoC Implementation combining Stack Moonwalking and Memory Encryption.

## TL;DR

Moonwalk++ is a PoC implementation of an enahnced version of [StackMoonwalk](https://github.com/klezVirus/SilentMoonwalk), which combines its original technique to remove the caller from the call stack, with a memory self-encryption routine, using ROP to both desynchronize unwinding from control flow and simultaneously encrypt the executing shellcode to hide it from inpection.

**Read more in the Blog Post:** [Malware Just Got Its Free Passes Back!](https://klezvirus.github.io/posts/Moonwalk-plus-plus/). 

## Is it Moonwalk++? (or minus minus --?)

GitHub will not allow the name to contain `+`, so well, it is named `--` but should have been `++`. Give or take, who cares?

## Overview

This repository demonstrates a PoC implementation to spoof the call stack when calling arbitrary Windows APIs, while simultanously encrypt the executing shellcode. 

An extensive overview of the technique and why it was developed can be read [here](https://klezvirus.github.io/posts/Moonwalk-plus-plus/).

This POC was made to work ONLY when injecting to `OneDrive.exe`. As such, in order to replicate its behaviour, you would need to ensure OneDrive is installed and running. Afterwards, retrieve one of the PID the program instantiates:

```powershell
(Get-Process OneDrive) | ForEach-Object {Write-Host $_.Id}
```

And provide the tool with one of them:

```bash
Moonwalk++ <PID-of-OneDrive>
```

### Injection

The POC is expecting a PID of `OneDrive.exe` to be provided as a CLI argument. The first frame is selected from the `OneDrive.exe` executable loaded from a well-defined location (i.e. `C:\Program Files\Microsoft OneDrive\OneDrive.exe`)

### OPSEC.. what?

This proof of concept has minimal operational security and is intentionally rough. Its primary purpose is to substantiate the theoretical claims discussed in the blog post [Malware Just Got Its Free Passes Back!](https://klezvirus.github.io/posts/Moonwalk-plus-plus/). 

## Build

In order to build the POC and observe a similar behaviour to the one in the picture, ensure to:

* Disable GS (`/GS-`)
* Disable Code Optimisation (`/Od`)
* Disable Whole Program Optimisation (Remove `/GL`)
* Disable size and speed preference (Remove `/Os`, `/Ot`)
* **Enable** intrinsic if not enabled (`/Oi`)

## Previous Work and Credits

Check [SilentMoowalk#PreviousWork](https://github.com/klezVirus/SilentMoonwalk?tab=readme-ov-file#previous-work).

## Notes

* This POC was made only to support and proof the feasibility to combine Stack Moonwalk and Memory Encryption. As the previous POC (SilentMoonwalk), it is not production ready and needs a lot of testing before integrating into C2 frameworks or similar. Use at your own risk.
* I'm not planning extensions for this technique, at least for now.