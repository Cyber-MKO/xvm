//! Non-local jumps: `_setjmp3`, `longjmp`.
//!
//! `setjmp` returns twice, so both are assembly, reached by thunks that
//! skip the realigning trampoline (`EmuExport::Raw`) and so see the
//! caller's own stack. The jump buffer follows `_JUMP_BUFFER` in setjmp.h:
//! Ebp, Ebx, Edi, Esi, Esp, Eip, Registration (the SEH chain at `fs:[0]`).
//! `longjmp` restores them and makes `setjmp` return its value, or 1 for
//! 0, as the longjmp page on Microsoft Learn says. It does not run
//! unwind handlers of the frames it leaves: C code has none.

std::arch::global_asm!(
    ".globl xvm_setjmp3",
    "xvm_setjmp3:",
    "mov edx, [esp + 4]",
    "mov [edx], ebp",
    "mov [edx + 4], ebx",
    "mov [edx + 8], edi",
    "mov [edx + 12], esi",
    "lea ecx, [esp + 4]",
    "mov [edx + 16], ecx",
    "mov ecx, [esp]",
    "mov [edx + 20], ecx",
    "mov ecx, fs:[0]",
    "mov [edx + 24], ecx",
    "xor eax, eax",
    "ret",
    ".globl xvm_longjmp",
    "xvm_longjmp:",
    "mov edx, [esp + 4]",
    "mov eax, [esp + 8]",
    "test eax, eax",
    "jnz 2f",
    "inc eax",
    "2:",
    "mov ecx, [edx + 24]",
    "mov fs:[0], ecx",
    "mov ebp, [edx]",
    "mov ebx, [edx + 4]",
    "mov edi, [edx + 8]",
    "mov esi, [edx + 12]",
    "mov esp, [edx + 16]",
    "jmp dword ptr [edx + 20]",
);

unsafe extern "C" {
    fn xvm_setjmp3();
    fn xvm_longjmp();
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_setjmp3", xvm_setjmp3 as *const () as u32),
        ("longjmp", xvm_longjmp as *const () as u32),
    ]
}
