#THIS IS VIBE CODED!

"""
IDA-Style Auto Comments for Binary Ninja
==========================================

Recreates IDA Pro's "auto comments" feature: short, generic, per-instruction
semantic comments like:

    sub  eax, 2      ; Integer Subtraction
    jz   loc_140060B2 ; Jump if Zero (ZF=1)
    cmp  eax, 2      ; Compare Two Operands
    xor  edx, edx    ; Zero out register / th32ProcessID (arg hint)

Install:
    Copy this file into your Binary Ninja plugins folder:
      Windows: %APPDATA%\\Binary Ninja\\plugins\\
      macOS:   ~/Library/Application Support/Binary Ninja/plugins/
      Linux:   ~/.binaryninja/plugins/
    Restart Binary Ninja.

Use:
    Right-click in a disassembly/IL view -> Plugins ->
      "Auto Comment: Current Function"
      "Auto Comment: Whole Binary"
      "Auto Comment: Remove Auto Comments (Current Function)"

Notes:
    - Comments are prefixed with "AC: " so the plugin can find/strip its own
      comments later without touching manual notes you've added.
    - By default existing (non-AC) comments are preserved; AC comments are
      appended on a new line if you re-run the plugin.
    - This is heuristic / mnemonic-based, same spirit as IDA's generic
      comments -- it does NOT do full data-flow analysis. It's meant to make
      raw disassembly more readable at a glance, not to replace real
      analysis.
"""

import re
from binaryninja import (
    PluginCommand,
    BinaryView,
    Function,
    InstructionTextTokenType,
    BackgroundTaskThread,
)

AC_PREFIX = "AC: "

# ---------------------------------------------------------------------------
# Mnemonic -> generic description (x86 / x86_64). Extend freely.
# ---------------------------------------------------------------------------
MNEMONIC_DESCRIPTIONS = {
    # Data movement
    "mov": "Move",
    "movzx": "Move with Zero-Extend",
    "movsx": "Move with Sign-Extend",
    "movsxd": "Move with Sign-Extend (Dword)",
    "lea": "Load Effective Address",
    "xchg": "Exchange",
    "push": "Push onto Stack",
    "pop": "Pop off Stack",
    "cmovz": "Move if Zero (ZF=1)",
    "cmove": "Move if Equal (ZF=1)",
    "cmovnz": "Move if Not Zero (ZF=0)",
    "cmovne": "Move if Not Equal (ZF=0)",
    "cmovl": "Move if Less (SF!=OF)",
    "cmovnge": "Move if Not Greater or Equal (SF!=OF)",
    "cmovg": "Move if Greater (ZF=0 & SF=OF)",
    "cmovnle": "Move if Not Less or Equal (ZF=0 & SF=OF)",
    "cmovle": "Move if Less or Equal (ZF=1 | SF!=OF)",
    "cmovng": "Move if Not Greater (ZF=1 | SF!=OF)",
    "cmovge": "Move if Greater or Equal (SF=OF)",
    "cmovnl": "Move if Not Less (SF=OF)",
    "cmovs": "Move if Sign (SF=1)",
    "cmovns": "Move if Not Sign (SF=0)",
    "cmovo": "Move if Overflow (OF=1)",
    "cmovno": "Move if Not Overflow (OF=0)",
    "cmovc": "Move if Carry (CF=1)",
    "cmovb": "Move if Below (CF=1)",
    "cmovnae": "Move if Not Above or Equal (CF=1)",
    "cmovnc": "Move if Not Carry (CF=0)",
    "cmovae": "Move if Above or Equal (CF=0)",
    "cmovnb": "Move if Not Below (CF=0)",
    "cmovbe": "Move if Below or Equal (CF=1 | ZF=1)",
    "cmovna": "Move if Not Above (CF=1 | ZF=1)",
    "cmova": "Move if Above (CF=0 & ZF=0)",
    "cmovnbe": "Move if Not Below or Equal (CF=0 & ZF=0)",
    "cmovp": "Move if Parity (PF=1)",
    "cmovpe": "Move if Parity Even (PF=1)",
    "cmovnp": "Move if Not Parity (PF=0)",
    "cmovpo": "Move if Parity Odd (PF=0)",
    "movabs": "Move Immediate 64-bit Value",
    "movbe": "Move Data After Swapping Bytes",
    "bswap": "Byte Swap (endianness flip)",
    "xadd": "Exchange and Add",
    "cmpxchg": "Compare and Exchange",
    "cmpxchg8b": "Compare and Exchange 8 Bytes",
    "cmpxchg16b": "Compare and Exchange 16 Bytes",

    # Arithmetic
    "add": "Integer Addition",
    "adc": "Add with Carry",
    "sub": "Integer Subtraction",
    "sbb": "Subtract with Borrow",
    "inc": "Increment by 1",
    "dec": "Decrement by 1",
    "neg": "Two's Complement Negation",
    "mul": "Unsigned Multiply",
    "imul": "Signed Multiply",
    "div": "Unsigned Divide",
    "idiv": "Signed Divide",
    "cdq": "Sign-Extend EAX into EDX:EAX",
    "cwd": "Sign-Extend AX into DX:AX",
    "cqo": "Sign-Extend RAX into RDX:RAX",
    "cbw": "Sign-Extend AL into AX",

    # Logic / bitwise
    "and": "Logical AND",
    "or": "Logical OR",
    "xor": "Logical Exclusive OR",
    "not": "One's Complement Negation",
    "shl": "Shift Left",
    "sal": "Shift Arithmetic Left",
    "shr": "Shift Right (Logical)",
    "sar": "Shift Right (Arithmetic)",
    "rol": "Rotate Left",
    "ror": "Rotate Right",
    "rcl": "Rotate Left through Carry",
    "rcr": "Rotate Right through Carry",
    "bt": "Bit Test",
    "bts": "Bit Test and Set",
    "btr": "Bit Test and Reset",
    "btc": "Bit Test and Complement",
    "bsf": "Bit Scan Forward",
    "bsr": "Bit Scan Reverse",

    # Comparison / test
    "cmp": "Compare Two Operands",
    "test": "Logical Compare (AND, sets flags only)",

    # Control flow - unconditional
    "jmp": "Unconditional Jump",
    "call": "Call Procedure",
    "ret": "Return from Procedure",
    "retn": "Return from Procedure",
    "leave": "High Level Procedure Exit",
    "nop": "No Operation",
    "int3": "Breakpoint (Trap to Debugger)",
    "hlt": "Halt",
    "syscall": "Fast System Call",

    # Conditional jumps (flag semantics, IDA-style)
    "jz": "Jump if Zero (ZF=1)",
    "je": "Jump if Equal (ZF=1)",
    "jnz": "Jump if Not Zero (ZF=0)",
    "jne": "Jump if Not Equal (ZF=0)",
    "js": "Jump if Sign (SF=1)",
    "jns": "Jump if Not Sign (SF=0)",
    "jo": "Jump if Overflow (OF=1)",
    "jno": "Jump if Not Overflow (OF=0)",
    "jc": "Jump if Carry (CF=1)",
    "jb": "Jump if Below (CF=1)",
    "jnae": "Jump if Not Above or Equal (CF=1)",
    "jnc": "Jump if Not Carry (CF=0)",
    "jae": "Jump if Above or Equal (CF=0)",
    "jnb": "Jump if Not Below (CF=0)",
    "jbe": "Jump if Below or Equal (CF=1 | ZF=1)",
    "jna": "Jump if Not Above (CF=1 | ZF=1)",
    "ja": "Jump if Above (CF=0 & ZF=0)",
    "jnbe": "Jump if Not Below or Equal (CF=0 & ZF=0)",
    "jl": "Jump if Less (SF!=OF)",
    "jnge": "Jump if Not Greater or Equal (SF!=OF)",
    "jge": "Jump if Greater or Equal (SF=OF)",
    "jnl": "Jump if Not Less (SF=OF)",
    "jle": "Jump if Less or Equal (ZF=1 | SF!=OF)",
    "jng": "Jump if Not Greater (ZF=1 | SF!=OF)",
    "jg": "Jump if Greater (ZF=0 & SF=OF)",
    "jnle": "Jump if Not Less or Equal (ZF=0 & SF=OF)",
    "jp": "Jump if Parity (PF=1)",
    "jpe": "Jump if Parity Even (PF=1)",
    "jnp": "Jump if Not Parity (PF=0)",
    "jpo": "Jump if Parity Odd (PF=0)",
    "jcxz": "Jump if CX is Zero",
    "jecxz": "Jump if ECX is Zero",
    "jrcxz": "Jump if RCX is Zero",

    # Conditional set
    "setz": "Set Byte if Zero (ZF=1)",
    "sete": "Set Byte if Equal (ZF=1)",
    "setnz": "Set Byte if Not Zero (ZF=0)",
    "setne": "Set Byte if Not Equal (ZF=0)",
    "setl": "Set Byte if Less (SF!=OF)",
    "setg": "Set Byte if Greater (ZF=0 & SF=OF)",
    "setle": "Set Byte if Less or Equal (ZF=1 | SF!=OF)",
    "setge": "Set Byte if Greater or Equal (SF=OF)",
    "seta": "Set Byte if Above (CF=0 & ZF=0)",
    "setb": "Set Byte if Below (CF=1)",
    "setae": "Set Byte if Above or Equal (CF=0)",
    "setbe": "Set Byte if Below or Equal (CF=1 | ZF=1)",

    # Loop
    "loop": "Decrement CX/ECX/RCX and Loop if != 0",
    "loope": "Loop if Equal (ZF=1)",
    "loopz": "Loop if Zero (ZF=1)",
    "loopne": "Loop if Not Equal (ZF=0)",
    "loopnz": "Loop if Not Zero (ZF=0)",

    # String / misc
    "movs": "Move String",
    "movsb": "Move String (Byte)",
    "movsw": "Move String (Word)",
    "movsd": "Move String (Dword)",
    "stos": "Store String",
    "stosb": "Store String (Byte)",
    "stosd": "Store String (Dword)",
    "lods": "Load String",
    "scas": "Scan String",
    "cmps": "Compare String",
    "rep": "Repeat Prefix",
    "repe": "Repeat while Equal Prefix",
    "repne": "Repeat while Not Equal Prefix",

    # Stack frame
    "enter": "High Level Procedure Entry",

    # Flags
    "clc": "Clear Carry Flag",
    "stc": "Set Carry Flag",
    "cld": "Clear Direction Flag",
    "std": "Set Direction Flag",
    "cli": "Clear Interrupt Flag",
    "sti": "Set Interrupt Flag",
    "pushf": "Push Flags Register",
    "popf": "Pop Flags Register",
    "pushfq": "Push RFLAGS",
    "popfq": "Pop RFLAGS",

    # System / misc
    "cpuid": "CPU Identification",
    "rdtsc": "Read Time-Stamp Counter",
    "rdtscp": "Read Time-Stamp Counter and Processor ID",
    "pause": "Spin-Loop Hint (SMT-friendly no-op)",
    "endbr64": "Indirect Branch Target Marker (CET, 64-bit)",
    "endbr32": "Indirect Branch Target Marker (CET, 32-bit)",
    "ud0": "Undefined Instruction (intentional trap)",
    "ud1": "Undefined Instruction (intentional trap)",
    "ud2": "Undefined Instruction (intentional trap)",
    "lahf": "Load Flags into AH",
    "sahf": "Store AH into Flags",
    "xlat": "Table Lookup Translation",
    "xlatb": "Table Lookup Translation",
    "in": "Input from Port",
    "out": "Output to Port",
    "insb": "Input String (Byte)",
    "insw": "Input String (Word)",
    "insd": "Input String (Dword)",
    "outsb": "Output String (Byte)",
    "outsw": "Output String (Word)",
    "outsd": "Output String (Dword)",
    "iret": "Interrupt Return",
    "iretd": "Interrupt Return (32-bit)",
    "iretq": "Interrupt Return (64-bit)",
    "callf": "Far Call",
    "jmpf": "Far Jump",
    "retf": "Far Return",
    "wait": "Wait for FPU",
    "fwait": "Wait for FPU",
    "wbinvd": "Write Back and Invalidate Cache",
    "invd": "Invalidate Cache (no writeback)",
    "invlpg": "Invalidate TLB Entry",
    "swapgs": "Swap GS Base Register (kernel/user)",
    "sysenter": "Fast System Call Entry",
    "sysexit": "Fast System Call Exit",
    "sysret": "Return from Fast System Call",
    "rdmsr": "Read Model-Specific Register",
    "wrmsr": "Write Model-Specific Register",
    "xgetbv": "Get Extended Control Register",
    "xsetbv": "Set Extended Control Register",

    # SSE / SSE2 / AVX (common in modern optimized binaries)
    "movaps": "Move Aligned Packed Single-Precision Floats",
    "movups": "Move Unaligned Packed Single-Precision Floats",
    "movapd": "Move Aligned Packed Double-Precision Floats",
    "movupd": "Move Unaligned Packed Double-Precision Floats",
    "movdqa": "Move Aligned Packed Integers (128-bit)",
    "movdqu": "Move Unaligned Packed Integers (128-bit)",
    "movss": "Move Scalar Single-Precision Float",
    "movd": "Move Doubleword (to/from XMM/MMX)",
    "movq": "Move Quadword (to/from XMM/MMX)",
    "pxor": "Packed Logical XOR (often used to zero a register)",
    "xorps": "Bitwise XOR Packed Single-Precision (often zeroing idiom)",
    "andps": "Bitwise AND Packed Single-Precision",
    "andnps": "Bitwise AND-NOT Packed Single-Precision",
    "orps": "Bitwise OR Packed Single-Precision",
    "addss": "Add Scalar Single-Precision Float",
    "addsd": "Add Scalar Double-Precision Float",
    "subss": "Subtract Scalar Single-Precision Float",
    "subsd": "Subtract Scalar Double-Precision Float",
    "mulss": "Multiply Scalar Single-Precision Float",
    "mulsd": "Multiply Scalar Double-Precision Float",
    "divss": "Divide Scalar Single-Precision Float",
    "divsd": "Divide Scalar Double-Precision Float",
    "comiss": "Compare Scalar Single-Precision (sets EFLAGS)",
    "comisd": "Compare Scalar Double-Precision (sets EFLAGS)",
    "ucomiss": "Unordered Compare Scalar Single-Precision (sets EFLAGS)",
    "ucomisd": "Unordered Compare Scalar Double-Precision (sets EFLAGS)",
    "cvtsi2sd": "Convert Signed Integer to Scalar Double-Precision Float",
    "cvtsi2ss": "Convert Signed Integer to Scalar Single-Precision Float",
    "cvttsd2si": "Convert Scalar Double-Precision Float to Integer (truncate)",
    "cvttss2si": "Convert Scalar Single-Precision Float to Integer (truncate)",
    "cvtss2sd": "Convert Scalar Single-Precision to Double-Precision Float",
    "cvtsd2ss": "Convert Scalar Double-Precision to Single-Precision Float",
    "pshufd": "Shuffle Packed Doublewords",
    "punpcklqdq": "Unpack Low Quadwords",
    "vzeroupper": "Zero Upper Bits of YMM Registers (AVX/SSE transition)",

    # x87 FPU
    "fld": "Load Floating-Point Value onto FPU Stack",
    "fst": "Store Floating-Point Value",
    "fstp": "Store Floating-Point Value and Pop",
    "fild": "Load Integer onto FPU Stack (as float)",
    "fist": "Store as Integer",
    "fistp": "Store as Integer and Pop",
    "fadd": "FPU Add",
    "faddp": "FPU Add and Pop",
    "fiadd": "FPU Add Integer",
    "fsub": "FPU Subtract",
    "fsubp": "FPU Subtract and Pop",
    "fisub": "FPU Subtract Integer",
    "fmul": "FPU Multiply",
    "fmulp": "FPU Multiply and Pop",
    "fimul": "FPU Multiply Integer",
    "fdiv": "FPU Divide",
    "fdivp": "FPU Divide and Pop",
    "fidiv": "FPU Divide Integer",
    "fcom": "FPU Compare",
    "fcomp": "FPU Compare and Pop",
    "fcompp": "FPU Compare and Pop Twice",
    "fucom": "FPU Unordered Compare",
    "fucomp": "FPU Unordered Compare and Pop",
    "fucompp": "FPU Unordered Compare and Pop Twice",
    "fchs": "FPU Change Sign",
    "fabs": "FPU Absolute Value",
    "fsqrt": "FPU Square Root",
    "fxch": "FPU Exchange Register Contents",
    "fnstsw": "Store FPU Status Word (no wait)",
    "fstsw": "Store FPU Status Word",
    "fnstcw": "Store FPU Control Word (no wait)",
    "fldcw": "Load FPU Control Word",
    "fld1": "Load Constant 1.0 onto FPU Stack",
    "fldz": "Load Constant 0.0 onto FPU Stack",
}

# Well-known Windows API param registers right before a call, purely cosmetic
# hint like the "; th32ProcessID" / "; dwFlags" you see in the IDA screenshot.
# This is intentionally NOT comprehensive -- just a small illustrative set for
# CreateToolhelp32Snapshot, which is what triggered this request.
KNOWN_CALL_ARG_HINTS = {
    "createtoolhelp32snapshot": ["dwFlags", "th32ProcessID"],  # right-to-left push/set order in the screenshot
}


def get_mnemonic(tokens):
    """Extract the plain mnemonic string from an instruction's text tokens."""
    for tok in tokens:
        if tok.type in (
            InstructionTextTokenType.InstructionToken,
            InstructionTextTokenType.OpcodeToken,
        ):
            return tok.text.strip().lower()
    return None


def describe_instruction(mnemonic):
    if not mnemonic:
        return None
    # normalize things like "rep stosd" -> take the last real mnemonic
    parts = mnemonic.split()
    base = parts[-1]
    return MNEMONIC_DESCRIPTIONS.get(base)


# ---------------------------------------------------------------------------
# Operand-aware hints: decode hex immediates to decimal (and ASCII, when the
# byte value is printable) and describe what's actually being compared /
# assigned / shifted, e.g.:
#   cmp eax, 0x18      -> "Compare Two Operands (EAX vs 24)"
#   cmp al, 41h        -> "Compare Two Operands (AL vs 65 / 'A')"
#   sub eax, 0Dh       -> "Integer Subtraction (EAX -= 13)"
#   shl ecx, 4         -> "Shift Left (ECX << 4)"
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Operand-aware hints: decode hex immediates to decimal/signed values and
# stack-string style ASCII, and describe what's actually being compared /
# assigned / shifted, e.g.:
#   cmp eax, 0x18            -> "Compare Two Operands (EAX vs 24)"
#   cmp al, 41h               -> "Compare Two Operands (AL vs 65 / 'A')"
#   sub eax, 0Dh               -> "Integer Subtraction (EAX -= 13)"
#   cmp eax, 0xFFFFFFFF        -> "Compare Two Operands (EAX vs 4294967295 (signed: -1))"
#   shl ecx, 4                 -> "Shift Left (ECX << 4)"
#   mov dword [rbp-0x10], 0x6c6c6548 -> "Move (= 1819043144 -> "Hell")"
#
# This tries to mimic what IDA does when it shows you the decimal/ASCII
# meaning of an otherwise-opaque hex literal, including the classic
# "packed ASCII pushed onto the stack" pattern used to build strings without
# a .rodata reference (very common in shellcode / stack-string CTF tasks).
# ---------------------------------------------------------------------------
ARITH_ASSIGN_SYMBOLS = {
    "add": "+=",
    "adc": "+=",
    "sub": "-=",
    "sbb": "-=",
    "and": "&=",
    "or": "|=",
    "xor": "^=",
}

SHIFT_SYMBOLS = {
    "shl": "<<",
    "sal": "<<",
    "shr": ">>",
    "sar": ">>",
    "rol": "rol",
    "ror": "ror",
}

CMP_LIKE_MNEMONICS = {"cmp", "test"}

# Explicit size-specifier keywords Binary Ninja/other disassemblers print
# before a memory operand ("dword [rbp-0x10]") -- used to figure out how wide
# an immediate written to memory actually is, since there's no register token
# to infer width from in that case.
SIZE_KEYWORD_BITS = {
    "byte": 8,
    "word": 16,
    "dword": 32,
    "qword": 64,
}

# Register name -> width in bits, covering the standard x86/x86_64 GPRs
# (8/16/32/64-bit forms, including the r8-r15 extended registers).
REGISTER_BITS = {}
for _n in ("a", "b", "c", "d"):
    REGISTER_BITS["r" + _n + "x"] = 64
    REGISTER_BITS["e" + _n + "x"] = 32
    REGISTER_BITS[_n + "x"] = 16
    REGISTER_BITS[_n + "l"] = 8
    REGISTER_BITS[_n + "h"] = 8
for _n in ("si", "di", "bp", "sp"):
    REGISTER_BITS["r" + _n] = 64
    REGISTER_BITS["e" + _n] = 32
    REGISTER_BITS[_n] = 16
    REGISTER_BITS[_n + "l"] = 8  # sil, dil, bpl, spl
for _i in range(8, 16):
    REGISTER_BITS["r%d" % _i] = 64
    REGISTER_BITS["r%dd" % _i] = 32
    REGISTER_BITS["r%dw" % _i] = 16
    REGISTER_BITS["r%db" % _i] = 8
del _n, _i

# Bracket-depth tracking uses the literal '[' / ']' characters in each
# token's text rather than a specific Begin/EndMemoryOperandToken enum
# member. Some Binary Ninja architecture plugins don't emit that dedicated
# token type for x86 memory operands (bracket text is just part of ordinary
# TextToken/RegisterToken text), which silently broke bracket-awareness. The
# character-based approach works regardless of exactly how the tokens are
# typed, since Intel-syntax memory operands always use literal brackets.


def get_base_mnemonic(mnemonic):
    if not mnemonic:
        return None
    return mnemonic.split()[-1]


def extract_top_level_operands(tokens):
    """Find the first register and first immediate that are NOT inside a
    memory operand's brackets, e.g. for `mov [rbp-0x10], 0x41` this correctly
    ignores 'rbp' and '-0x10' and picks up only the real source immediate,
    and for `test byte [rcx+rax+0x3], 0xf` ignores the address registers and
    the +0x3 displacement, picking up only the real comparison value 0xf."""
    depth = 0
    reg = None
    imm = None
    for tok in tokens:
        text = getattr(tok, "text", "") or ""
        opens = text.count("[")
        closes = text.count("]")
        depth += opens
        if depth == 0:
            ttype = tok.type
            if reg is None and ttype == InstructionTextTokenType.RegisterToken:
                reg = text.upper()
            elif imm is None and ttype in (
                InstructionTextTokenType.IntegerToken,
                InstructionTextTokenType.PossibleAddressToken,
            ):
                imm = getattr(tok, "value", None)
        depth = max(0, depth - closes)
    return reg, imm



def infer_operand_bits(tokens, reg):
    """Best-effort operand width: explicit size keyword > register width > 32-bit default."""
    for tok in tokens:
        text = getattr(tok, "text", "") or ""
        bits = SIZE_KEYWORD_BITS.get(text.strip().lower())
        if bits:
            return bits
    if reg:
        return REGISTER_BITS.get(reg.lower(), 32)
    return 32


def format_immediate(value, bits):
    """Render an immediate as its decimal value, plus a signed form when the
    sign bit is set for its width, plus a printable-char note for single bytes."""
    try:
        raw = int(value) & ((1 << bits) - 1)
    except (TypeError, ValueError):
        return None
    signed = raw - (1 << bits) if raw >= (1 << (bits - 1)) else raw

    if value is not None and int(value) < 0:
        primary, secondary, secondary_label = signed, raw, "unsigned"
    else:
        primary, secondary, secondary_label = raw, signed, "signed"

    text = str(primary)
    if secondary != primary:
        text += " (%s: %d)" % (secondary_label, secondary)

    byte = raw & 0xFF
    if 0x20 <= byte <= 0x7E:
        text += " / '%s'" % chr(byte)
    return text


def decode_ascii_run(value, bits):
    """Decode a multi-byte immediate as little-endian ASCII, e.g. the classic
    `mov [rbp-0x10], 0x6c6c6548` stack-string idiom -> 'Hell'. Returns None
    unless every byte is printable ASCII and there are at least 2 of them."""
    nbytes = bits // 8
    if nbytes < 2:
        return None
    try:
        raw = int(value) & ((1 << bits) - 1)
        b = raw.to_bytes(nbytes, "little")
    except (TypeError, ValueError, OverflowError):
        return None
    if all(0x20 <= c <= 0x7E for c in b):
        return b.decode("ascii")
    return None


def operand_hint(mnemonic, tokens):
    """Build a short 'REG op VALUE' style hint from an instruction's operands, if useful."""
    base = get_base_mnemonic(mnemonic)
    if not base:
        return None

    reg, imm = extract_top_level_operands(tokens)
    if imm is None:
        return None

    bits = infer_operand_bits(tokens, reg)

    imm_str = format_immediate(imm, bits)
    core = None

    if base in CMP_LIKE_MNEMONICS:
        core = "%s vs %s" % (reg, imm_str) if reg else "vs %s" % imm_str
    elif base in ARITH_ASSIGN_SYMBOLS:
        sym = ARITH_ASSIGN_SYMBOLS[base]
        core = "%s %s %s" % (reg, sym, imm_str) if reg else "%s %s" % (sym, imm_str)
    elif base == "mov":
        core = "%s = %s" % (reg, imm_str) if reg else "= %s" % imm_str
    elif base in SHIFT_SYMBOLS:
        sym = SHIFT_SYMBOLS[base]
        core = "%s %s %s" % (reg, sym, imm_str) if reg else "%s %s" % (sym, imm_str)

    # Stack-string / packed-ASCII detection applies regardless of mnemonic --
    # e.g. `push 0x6c6c6548` in shellcode-style string construction.
    ascii_str = decode_ascii_run(imm, bits)
    if ascii_str:
        note = '"%s"' % ascii_str
        core = "%s -> %s" % (core, note) if core else note

    return core


def strip_ac_comment(existing):
    """Remove only the AC-authored line(s) from an existing comment, keep the rest."""
    if not existing:
        return None
    lines = [l for l in existing.split("\n") if not l.startswith(AC_PREFIX)]
    return "\n".join(lines) if lines else None


def set_auto_comment(bv, addr, text):
    existing = bv.get_comment_at(addr)
    kept = strip_ac_comment(existing)
    new_line = AC_PREFIX + text
    if kept:
        combined = kept + "\n" + new_line
    else:
        combined = new_line
    bv.set_comment_at(addr, combined)


def remove_auto_comments_in_function(bv, func):
    for block in func.basic_blocks:
        addr = block.start
        for tokens, length in block:
            existing = bv.get_comment_at(addr)
            if existing:
                kept = strip_ac_comment(existing)
                if kept:
                    bv.set_comment_at(addr, kept)
                else:
                    bv.set_comment_at(addr, "")
            addr += length


def annotate_function(bv, func):
    count = 0
    for block in func.basic_blocks:
        addr = block.start
        for tokens, length in block:
            mnemonic = get_mnemonic(tokens)
            desc = describe_instruction(mnemonic)
            if desc:
                hint = operand_hint(mnemonic, tokens)
                if hint:
                    desc = "%s (%s)" % (desc, hint)
                set_auto_comment(bv, addr, desc)
                count += 1
            addr += length
    return count


class AutoCommentTask(BackgroundTaskThread):
    def __init__(self, bv, functions, label):
        BackgroundTaskThread.__init__(self, label, True)
        self.bv = bv
        self.functions = functions

    def run(self):
        total = 0
        n = len(self.functions)
        for i, func in enumerate(self.functions):
            if self.cancelled:
                break
            self.progress = "Auto Comment: %d/%d functions" % (i + 1, n)
            total += annotate_function(self.bv, func)
        self.bv.update_analysis_and_wait() if hasattr(self.bv, "update_analysis_and_wait") else None
        print("Auto Comment: annotated %d instructions across %d functions" % (total, n))


def cmd_current_function(bv, func):
    task = AutoCommentTask(bv, [func], "Auto Comment: Current Function")
    task.start()


def cmd_whole_binary(bv):
    funcs = list(bv.functions)
    task = AutoCommentTask(bv, funcs, "Auto Comment: Whole Binary")
    task.start()


def cmd_remove_current_function(bv, func):
    remove_auto_comments_in_function(bv, func)
    print("Auto Comment: removed AC comments in %s" % func.name)


PluginCommand.register_for_function(
    "Auto Comment\\Current Function",
    "Add IDA-style generic instruction comments to the current function",
    cmd_current_function,
)

PluginCommand.register(
    "Auto Comment\\Whole Binary",
    "Add IDA-style generic instruction comments to every function in the binary",
    cmd_whole_binary,
)

PluginCommand.register_for_function(
    "Auto Comment\\Remove Auto Comments (Current Function)",
    "Remove only the comments added by this plugin, keeping manual notes",
    cmd_remove_current_function,
)
