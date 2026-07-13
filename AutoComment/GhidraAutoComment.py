# Add IDA-style generic instruction comments (with decoded immediates and
# stack-string detection) to the current function or the whole program.
# THIS WAS VIBE CODED!
"""
IDA-Style Auto Comments for Ghidra
====================================

Ghidra port of the same idea as the Binary Ninja version: short, generic,
per-instruction semantic comments like IDA's auto-comments, plus decoded
operand hints, e.g.:

    SUB  EAX, 0xd            ; Integer Subtraction (EAX -= 13)
    CMP  EAX, 0xffffffff     ; Compare Two Operands (EAX vs 4294967295 (signed: -1))
    TEST byte ptr [RCX + RAX + 0x3], 0xf
                              ; Logical Compare (AND, sets flags only) (vs 15)
    MOV  dword ptr [RBP + -0x10], 0x6c6c6548
                              ; Move (= 1819043144 / 'H' -> "Hell")

Install:
    Copy this file into your Ghidra scripts directory:
      ~/ghidra_scripts/   (default user scripts directory)
    Open the Script Manager (Window -> Script Manager, or the green play
    button in the toolbar), refresh, and it'll show up under the
    "CTF.Annotations" category. Double-click to run, or assign a keybinding.

Use:
    Running the script asks you to pick:
      - Annotate Current Function
      - Annotate Whole Program
      - Remove Auto Comments (Current Function)
      - Remove Auto Comments (Whole Program)

How operand hints work (and why this is more reliable than text scanning):
    Ghidra's Instruction API tells you directly whether an operand is a
    plain register, a plain scalar/immediate, or a DYNAMIC (memory/indirect)
    reference via getOperandType(). That means we don't have to guess at
    bracket characters in disassembly text to avoid misreading a memory
    operand's internal displacement (e.g. the "+0x8" in "[RAX + 0x8]") as
    if it were a real top-level immediate -- we just check the DYNAMIC bit.
    Immediates are decoded to decimal, shown as signed when the sign bit is
    set for their width (e.g. 0xFFFFFFFF -> "4294967295 (signed: -1)"), and
    multi-byte immediates are decoded as little-endian ASCII when every byte
    is printable, to catch the "packed string pushed as an immediate" idiom
    common in shellcode / stack-string CTF tasks.

Notes:
    - Comments are prefixed with "AC: " internally so the script can find
      and remove only its own annotations without touching comments you've
      written yourself. Existing comments are preserved; the AC line is
      appended.
    - Uses Ghidra's EOL (end-of-line) comment slot on each instruction, which
      shows in the Listing view. Whether/how it surfaces in the Decompiler
      window depends on Ghidra's own comment-carrying rules for the
      underlying address, same caveat as any other per-instruction comment.
    - This is heuristic / mnemonic-based, same spirit as IDA's generic
      comments -- it does NOT do full data-flow analysis.
"""

from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar

AC_PREFIX = "AC: "

# ---------------------------------------------------------------------------
# Mnemonic -> generic description (x86 / x86_64). Extend freely.
# Ghidra mnemonic strings are matched case-insensitively (lowercased below).
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

# ---------------------------------------------------------------------------
# Operand-aware hints: decode immediates to decimal/signed values and
# stack-string style ASCII, e.g.:
#   CMP EAX, 0x18                          -> "Compare Two Operands (EAX vs 24)"
#   SUB EAX, 0xd                           -> "Integer Subtraction (EAX -= 13)"
#   CMP EAX, 0xffffffff                    -> "... (EAX vs 4294967295 (signed: -1))"
#   TEST byte ptr [RCX + RAX + 0x3], 0xf   -> "... (vs 15)"   (displacement ignored)
#   MOV dword ptr [RBP + -0x10], 0x6c6c6548 -> "Move (= 1819043144 -> "Hell")"
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

CMP_LIKE_MNEMONICS = set(["cmp", "test"])


def get_base_mnemonic(instruction):
    return instruction.getMnemonicString().lower()


def extract_top_level_operands(instruction):
    """Find the first plain register and first plain scalar/immediate that
    are NOT part of a DYNAMIC (memory/indirect) operand. This is the Ghidra
    equivalent of the Binary Ninja plugin's bracket-depth tracking, but uses
    Ghidra's own operand-type flags instead of scanning disassembly text --
    e.g. for `TEST byte ptr [RCX + RAX + 0x3], 0xf` this correctly ignores
    RCX/RAX/0x3 (all part of the DYNAMIC memory operand) and picks up only
    the real comparison immediate, 0xf."""
    reg = None
    imm = None
    num_ops = instruction.getNumOperands()
    for i in range(num_ops):
        optype = instruction.getOperandType(i)
        if (optype & OperandType.DYNAMIC) != 0:
            continue
        if reg is None and (optype & OperandType.REGISTER) != 0:
            for obj in instruction.getOpObjects(i):
                if isinstance(obj, Register):
                    reg = obj
                    break
        if imm is None and (optype & OperandType.SCALAR) != 0:
            scalar = instruction.getScalar(i)
            if scalar is not None:
                imm = scalar
    return reg, imm


def format_immediate(value, bits):
    """Render an immediate as its decimal value, plus a signed form when the
    sign bit is set for its width, plus a printable-char note for single bytes."""
    raw = value & ((1 << bits) - 1)
    signed = raw - (1 << bits) if raw >= (1 << (bits - 1)) else raw

    if value < 0:
        primary, secondary, label = signed, raw, "unsigned"
    else:
        primary, secondary, label = raw, signed, "signed"

    text = str(primary)
    if secondary != primary:
        text += " (%s: %d)" % (label, secondary)

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
    raw = value & ((1 << bits) - 1)
    chars = []
    for i in range(nbytes):
        b = (raw >> (i * 8)) & 0xFF
        if b < 0x20 or b > 0x7E:
            return None
        chars.append(chr(b))
    return "".join(chars)


def operand_hint(instruction):
    """Build a short 'REG op VALUE' style hint from an instruction's operands, if useful."""
    base = get_base_mnemonic(instruction)
    reg, imm = extract_top_level_operands(instruction)
    if imm is None:
        return None

    reg_name = reg.getName() if reg is not None else None
    bits = reg.getBitLength() if reg is not None else imm.bitLength()
    if not bits:
        bits = 32

    value = imm.getUnsignedValue() if not imm.isSigned() else imm.getSignedValue()
    imm_str = format_immediate(value, bits)
    core = None

    if base in CMP_LIKE_MNEMONICS:
        core = "%s vs %s" % (reg_name, imm_str) if reg_name else "vs %s" % imm_str
    elif base in ARITH_ASSIGN_SYMBOLS:
        sym = ARITH_ASSIGN_SYMBOLS[base]
        core = "%s %s %s" % (reg_name, sym, imm_str) if reg_name else "%s %s" % (sym, imm_str)
    elif base == "mov":
        core = "%s = %s" % (reg_name, imm_str) if reg_name else "= %s" % imm_str
    elif base in SHIFT_SYMBOLS:
        sym = SHIFT_SYMBOLS[base]
        core = "%s %s %s" % (reg_name, sym, imm_str) if reg_name else "%s %s" % (sym, imm_str)

    # Stack-string / packed-ASCII detection applies regardless of mnemonic --
    # e.g. `push 0x6c6c6548` in shellcode-style string construction.
    ascii_str = decode_ascii_run(value, bits)
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


def set_auto_comment(instruction, text):
    existing = instruction.getComment(CodeUnit.EOL_COMMENT)
    kept = strip_ac_comment(existing)
    new_line = AC_PREFIX + text
    combined = (kept + "\n" + new_line) if kept else new_line
    instruction.setComment(CodeUnit.EOL_COMMENT, combined)


def clear_auto_comment(instruction):
    existing = instruction.getComment(CodeUnit.EOL_COMMENT)
    if not existing:
        return False
    kept = strip_ac_comment(existing)
    if kept != existing:
        instruction.setComment(CodeUnit.EOL_COMMENT, kept)
        return True
    return False


def describe_instruction(instruction):
    base = get_base_mnemonic(instruction)
    desc = MNEMONIC_DESCRIPTIONS.get(base)
    if not desc:
        return None
    hint = operand_hint(instruction)
    return "%s (%s)" % (desc, hint) if hint else desc


def annotate_instructions(instructions, label):
    count = 0
    total = 0
    monitor.setMessage("Auto Comment: %s" % label)
    for instruction in instructions:
        if monitor.isCancelled():
            break
        total += 1
        if total % 500 == 0:
            monitor.setMessage("Auto Comment: %s (%d processed)" % (label, total))
        desc = describe_instruction(instruction)
        if desc:
            set_auto_comment(instruction, desc)
            count += 1
    println("Auto Comment: annotated %d/%d instructions (%s)" % (count, total, label))


def remove_auto_comments(instructions, label):
    count = 0
    for instruction in instructions:
        if monitor.isCancelled():
            break
        if clear_auto_comment(instruction):
            count += 1
    println("Auto Comment: removed %d AC comments (%s)" % (count, label))


def run():
    choice = askChoice(
        "Auto Comment (IDA-style)",
        "Choose an action:",
        [
            "Annotate Current Function",
            "Annotate Whole Program",
            "Remove Auto Comments (Current Function)",
            "Remove Auto Comments (Whole Program)",
        ],
        "Annotate Current Function",
    )

    listing = currentProgram.getListing()

    if choice == "Annotate Current Function":
        func = getFunctionContaining(currentAddress)
        if func is None:
            popup("No function contains the current address.")
            return
        instrs = listing.getInstructions(func.getBody(), True)
        annotate_instructions(instrs, func.getName())

    elif choice == "Annotate Whole Program":
        instrs = listing.getInstructions(True)
        annotate_instructions(instrs, "whole program")

    elif choice == "Remove Auto Comments (Current Function)":
        func = getFunctionContaining(currentAddress)
        if func is None:
            popup("No function contains the current address.")
            return
        instrs = listing.getInstructions(func.getBody(), True)
        remove_auto_comments(instrs, func.getName())

    elif choice == "Remove Auto Comments (Whole Program)":
        instrs = listing.getInstructions(True)
        remove_auto_comments(instrs, "whole program")


run()
