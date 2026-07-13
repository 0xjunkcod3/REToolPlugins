# Description

IDA Pro ships with a unique feature called AutoComments that helps newer people to assembly understand quickly what certain instructions are doing. Due to the amount of instructions within x86/x64 I find myself even looking up what certain instructions do and want the easy option of just running a plugin to figure out the weird ones for me.

This project brings that same feature to **Binary Ninja** and **Ghidra**, since neither tool has it built in.

## What it does

For every instruction with a recognized mnemonic, the plugin/script adds a short comment describing what the instruction actually does — the same generic, mnemonic-level explanations IDA shows (e.g. `sub` → "Integer Subtraction", `jz` → "Jump if Zero (ZF=1)", `cmp` → "Compare Two Operands"). Covers ~270 x86/x64 mnemonics: data movement, arithmetic, logic/bitwise, comparisons, all conditional jump/set/cmov variants, loops, string ops, SSE/SSE2, x87 FPU, and system instructions.

On top of that, it goes a step further than IDA's plain auto-comments by decoding the actual operands where it can add real information instead of just restating the mnemonic:

- **Hex immediates get decoded to decimal** — `sub eax, 0Dh` → "Integer Subtraction (EAX -= 13)"
- **Large hex constants get a signed interpretation** — `cmp eax, 0xFFFFFFFF` → "Compare Two Operands (EAX vs 4294967295 (signed: -1))", so the classic "compare against -1" idiom in loop/error checks is readable at a glance
- **Byte-sized immediates show their ASCII char** — `cmp al, 41h` → "AL vs 65 / 'A'"
- **Multi-byte immediates get decoded as little-endian ASCII** to catch the "packed string" idiom used to build strings on the stack without a data reference — `mov dword [rbp-0x10], 0x6c6c6548` → "Move (= 1819043144 -> "Hell")". This also fires on bare `push`-based stack strings, which show up a lot in shellcode/stack-string CTF tasks.
- **Memory-operand displacements are correctly ignored** — for something like `test byte [rcx+rax+0x3], 0xf`, it picks up the real comparison value `0xf` and skips the address math, rather than mistakenly annotating the `+0x3` offset.

## Versions

- **Binary Ninja**: a plugin (`Binja.py`) registered under Plugins → Auto Comment, with commands for the current function, the whole binary, and removing its own comments without touching manual notes.
- **Ghidra**: a Jython GhidraScript (`Ghidra.py`) for the classic Script Manager, with the same current-function / whole-program / remove options via an interactive prompt.

Both are heuristic and mnemonic-based, the same spirit as IDA's generic comments — they don't do full data-flow analysis, they're meant to make raw disassembly readable at a glance without having to look up an unfamiliar instruction every time.
