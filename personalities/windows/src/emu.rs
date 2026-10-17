//! Emulated system DLLs as minimal in-memory PE32 images (brief, Decisions:
//! option C).
//!
//! The functions themselves are Rust. Each emulated DLL also gets a small
//! PE image, so `GetModuleHandle`, `GetProcAddress` and code that walks
//! module headers find a real DLL. Every export points at a thunk in the
//! image's `.text`:
//!
//! ```text
//! B8 imm32    mov eax, target
//! E9 rel32    jmp trampoline
//! ```
//!
//! Windows i386 code keeps the stack only 4-byte aligned, while our Rust
//! functions, built for i686 Linux, assume 16 bytes and use aligned SSE
//! stores. The trampoline, at the start of `.text`, bridges the two: it
//! aligns the stack, copies the caller's argument area (256 bytes, enough
//! for varargs functions such as `printf`), and calls the target. Then it
//! returns popping exactly as many argument bytes as the target popped:
//! none for cdecl, all of them for stdcall. `eax` and `edx` pass through.
//!
//! Data exports (variables such as `msvcrt!__initenv`) get a zeroed slot in
//! the image's writable `.data`, which the agent and our Rust code share.
//!
//! The thunks hold absolute targets and the export table holds RVAs, so the
//! image needs no relocations. It is built for the base it will be mapped at.

use crate::pe::{
    FILE_DLL, MACHINE_I386, OPTIONAL_MAGIC_PE32, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE,
};

/// The system DLLs the Wazuh 4.14.2 census found (docs/phase1-sizing.md):
/// the 19 it imports, plus `ntdll.dll`, which it looks up at run time.
/// Imports from these resolve to emulated modules, never to files.
pub const SYSTEM_DLLS: [&str; 20] = [
    "advapi32.dll",
    "comctl32.dll",
    "crypt32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "mpr.dll",
    "msvcrt.dll",
    "netapi32.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "shlwapi.dll",
    "user32.dll",
    "version.dll",
    "wevtapi.dll",
    "wintrust.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "wtsapi32.dll",
];

/// Mapped into every Windows process before its executable, whether it
/// imports them or not.
pub const ALWAYS_LOADED: [&str; 2] = ["ntdll.dll", "kernel32.dll"];

pub fn is_system_dll(name: &str) -> bool {
    SYSTEM_DLLS.iter().any(|d| d.eq_ignore_ascii_case(name))
}

const PAGE: u32 = 0x1000;
const THUNK_SIZE: u32 = 16;

/// The realigning trampoline every thunk jumps to, with the target in eax.
pub(crate) const TRAMPOLINE: [u8; 56] = [
    0x55, // push ebp
    0x89, 0xe5, // mov ebp, esp
    0x56, // push esi
    0x57, // push edi
    0x53, // push ebx
    0x81, 0xec, 0x00, 0x01, 0x00, 0x00, // sub esp, 256
    0x83, 0xe4, 0xf0, // and esp, -16
    0x89, 0xe7, // mov edi, esp
    0x8d, 0x75, 0x08, // lea esi, [ebp+8]
    0xb9, 0x40, 0x00, 0x00, 0x00, // mov ecx, 64
    0xfc, // cld
    0xf3, 0xa5, // rep movsd
    0x89, 0xe3, // mov ebx, esp
    0xff, 0xd0, // call eax
    0x89, 0xe1, // mov ecx, esp
    0x29, 0xd9, // sub ecx, ebx
    0x8d, 0x65, 0xf4, // lea esp, [ebp-12]
    0x5b, // pop ebx
    0x5f, // pop edi
    0x5e, // pop esi
    0x5d, // pop ebp
    0x50, // push eax
    0x8b, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    0x89, 0x44, 0x0c, 0x04, // mov [esp+ecx+4], eax
    0x58, // pop eax
    0x01, 0xcc, // add esp, ecx
    0xc3, // ret
];
/// Thunks start after the trampoline, 16-byte aligned.
const TRAMPOLINE_SPACE: u32 = (TRAMPOLINE.len() as u32).div_ceil(16) * 16;
const PE_OFFSET: usize = 0x40;
const OPTIONAL_SIZE: u16 = 0xe0;
const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const FILE_32BIT_MACHINE: u16 = 0x0100;
const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;

/// What an emulated DLL exports under one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmuExport {
    /// A function: the address of its Rust implementation.
    Code(u32),
    /// A function reached without the realigning trampoline, for code
    /// that must see the caller's own stack (`setjmp`). Its thunk is
    /// `mov eax, target; jmp eax`.
    Raw(u32),
    /// A variable of this many bytes, placed in the image's `.data`.
    /// Rust code reaches it through the export's address.
    Data(u32),
}

const DATA_ALIGN: u32 = 8;

/// The bytes of an emulated DLL laid out for `base`. File offsets equal
/// RVAs (FileAlignment is the page size), so the result is both the file
/// form and the memory form. Sections: `.text` (thunks), `.data` (data
/// exports, zeroed) and `.edata`.
pub fn build_image(dll_name: &str, base: u32, exports: &[(&str, EmuExport)]) -> Vec<u8> {
    let mut sorted: Vec<_> = exports.to_vec();
    // The export name table must be in ascending order (PE format).
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let count = sorted.len() as u32;

    // Where each export lives: a thunk in .text or a slot in .data.
    let text_rva = PAGE;
    let mut text_size = TRAMPOLINE_SPACE;
    let mut data_size = 0;
    let mut placed = Vec::new();
    for (_, export) in &sorted {
        match export {
            EmuExport::Code(_) | EmuExport::Raw(_) => {
                placed.push(text_size);
                text_size += THUNK_SIZE;
            }
            EmuExport::Data(size) => {
                placed.push(data_size);
                data_size = round_up(data_size + size, DATA_ALIGN);
            }
        }
    }
    let text_size = text_size.max(1);
    let data_size = data_size.max(1);
    let data_rva = text_rva + round_up(text_size, PAGE);
    let edata_rva = data_rva + round_up(data_size, PAGE);

    // .edata: directory, function table, name table, ordinal table, strings.
    let functions = edata_rva + 40;
    let names = functions + 4 * count;
    let ordinals = names + 4 * count;
    let mut strings = ordinals + 2 * count;
    let dll_name_rva = strings;
    strings += dll_name.len() as u32 + 1;
    let mut name_rvas = Vec::new();
    for (name, _) in &sorted {
        name_rvas.push(strings);
        strings += name.len() as u32 + 1;
    }
    let edata_size = strings - edata_rva;
    let size_of_image = edata_rva + round_up(edata_size, PAGE);

    let mut m = vec![0u8; size_of_image as usize];
    let mut w = Writer(&mut m);

    // DOS header: only e_magic and e_lfanew matter.
    w.bytes(0, b"MZ");
    w.u32(0x3c, PE_OFFSET as u32);

    w.bytes(PE_OFFSET, b"PE\0\0");
    let coff = PE_OFFSET + 4;
    w.u16(coff, MACHINE_I386);
    w.u16(coff + 2, 3);
    w.u16(coff + 16, OPTIONAL_SIZE);
    w.u16(
        coff + 18,
        FILE_EXECUTABLE_IMAGE | FILE_32BIT_MACHINE | FILE_DLL,
    );

    let opt = coff + 20;
    w.u16(opt, OPTIONAL_MAGIC_PE32);
    w.u32(opt + 4, text_size);
    w.u32(opt + 8, size_of_image - data_rva);
    w.u32(opt + 20, text_rva);
    w.u32(opt + 24, data_rva);
    w.u32(opt + 28, base);
    w.u32(opt + 32, PAGE);
    w.u32(opt + 36, PAGE);
    w.u16(opt + 40, 6);
    w.u16(opt + 48, 6);
    w.u32(opt + 56, size_of_image);
    w.u32(opt + 60, PAGE);
    w.u16(opt + 68, SUBSYSTEM_WINDOWS_CUI);
    w.u32(opt + 92, 16);
    w.u32(opt + 96, edata_rva);
    w.u32(opt + 100, edata_size);

    let sections = opt + OPTIONAL_SIZE as usize;
    w.section(
        sections,
        b".text",
        text_rva,
        text_size,
        SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
    );
    w.section(
        sections + 40,
        b".data",
        data_rva,
        data_size,
        SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE,
    );
    w.section(
        sections + 80,
        b".edata",
        edata_rva,
        edata_size,
        SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
    );

    let d = edata_rva as usize;
    w.u32(d + 12, dll_name_rva);
    w.u32(d + 16, 1);
    w.u32(d + 20, count);
    w.u32(d + 24, count);
    w.u32(d + 28, functions);
    w.u32(d + 32, names);
    w.u32(d + 36, ordinals);
    w.bytes(dll_name_rva as usize, dll_name.as_bytes());
    w.bytes(text_rva as usize, &TRAMPOLINE);

    for (i, ((name, export), offset)) in sorted.iter().zip(placed).enumerate() {
        let i = i as u32;
        let rva = match export {
            EmuExport::Code(target) => {
                let thunk = text_rva + offset;
                w.bytes(thunk as usize, &[0xb8]);
                w.u32(thunk as usize + 1, *target);
                w.bytes(thunk as usize + 5, &[0xe9]);
                let rel = text_rva.wrapping_sub(thunk + 10);
                w.u32(thunk as usize + 6, rel);
                thunk
            }
            EmuExport::Raw(target) => {
                let thunk = text_rva + offset;
                w.bytes(thunk as usize, &[0xb8]);
                w.u32(thunk as usize + 1, *target);
                w.bytes(thunk as usize + 5, &[0xff, 0xe0]);
                thunk
            }
            EmuExport::Data(_) => data_rva + offset,
        };
        w.u32((functions + 4 * i) as usize, rva);
        w.u32((names + 4 * i) as usize, name_rvas[i as usize]);
        w.u16((ordinals + 2 * i) as usize, i as u16);
        w.bytes(name_rvas[i as usize] as usize, name.as_bytes());
    }
    m
}

struct Writer<'a>(&'a mut [u8]);

impl Writer<'_> {
    fn bytes(&mut self, off: usize, b: &[u8]) {
        self.0[off..off + b.len()].copy_from_slice(b);
    }
    fn u16(&mut self, off: usize, v: u16) {
        self.bytes(off, &v.to_le_bytes());
    }
    fn u32(&mut self, off: usize, v: u32) {
        self.bytes(off, &v.to_le_bytes());
    }
    fn section(&mut self, off: usize, name: &[u8], rva: u32, size: u32, flags: u32) {
        self.bytes(off, name);
        self.u32(off + 8, size);
        self.u32(off + 12, rva);
        self.u32(off + 16, round_up(size, PAGE));
        self.u32(off + 20, rva);
        self.u32(off + 36, flags);
    }
}

fn round_up(n: u32, align: u32) -> u32 {
    n.div_ceil(align) * align
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{ExportTarget, Image};

    #[test]
    fn image_parses_with_sorted_exports_and_thunks() {
        let base = 0x7700_0000;
        let bytes = build_image(
            "kernel32.dll",
            base,
            &[
                ("SetLastError", EmuExport::Code(0x1234_5678)),
                ("GetLastError", EmuExport::Code(0x0abc_def0)),
                ("_iob", EmuExport::Data(96)),
                ("__initenv", EmuExport::Data(4)),
            ],
        );
        let image = Image::layout("kernel32.dll", &bytes).unwrap();
        assert!(image.headers.is_dll());
        assert_eq!(image.base, base);
        assert!(image.imports().unwrap().is_empty());

        let exports = image.exports().unwrap().unwrap();
        assert_eq!(exports.dll_name, "kernel32.dll");
        let names: Vec<_> = exports
            .entries
            .iter()
            .map(|e| e.name.clone().unwrap())
            .collect();
        assert_eq!(names, ["GetLastError", "SetLastError", "__initenv", "_iob"]);

        let text = &image.headers.sections[0];
        assert!(text.protection().execute);
        for (name, target) in [
            ("GetLastError", 0x0abc_def0u32),
            ("SetLastError", 0x1234_5678),
        ] {
            let ExportTarget::Rva(rva) = exports.by_name(name).unwrap().target else {
                panic!("{name} is a forwarder");
            };
            assert!(rva >= text.virtual_address && rva < text.virtual_address + text.virtual_size);
            let thunk = &image.memory[rva as usize..rva as usize + 10];
            assert_eq!(thunk[0], 0xb8);
            assert_eq!(u32::from_le_bytes(thunk[1..5].try_into().unwrap()), target);
            assert_eq!(thunk[5], 0xe9);
            let rel = u32::from_le_bytes(thunk[6..10].try_into().unwrap());
            assert_eq!(
                rva.wrapping_add(10).wrapping_add(rel),
                text.virtual_address,
                "jumps to the trampoline"
            );
        }

        let data = &image.headers.sections[1];
        assert_eq!(data.name, ".data");
        assert!(data.protection().write && !data.protection().execute);
        let slot = |name| match exports.by_name(name).unwrap().target {
            ExportTarget::Rva(rva) => rva,
            ref other => panic!("{other:?}"),
        };
        let (initenv, iob) = (slot("__initenv"), slot("_iob"));
        assert_eq!(initenv, data.virtual_address);
        assert_eq!(
            iob,
            initenv + 8,
            "slots are 8-byte aligned and do not overlap"
        );
        assert!(iob + 96 <= data.virtual_address + data.virtual_size);
    }

    #[test]
    fn empty_dll_still_parses() {
        let bytes = build_image("mpr.dll", 0x7800_0000, &[]);
        let image = Image::layout("mpr.dll", &bytes).unwrap();
        assert!(image.exports().unwrap().unwrap().entries.is_empty());
    }

    #[test]
    fn system_dll_names_match_case_insensitively() {
        assert!(is_system_dll("KERNEL32.dll"));
        assert!(!is_system_dll("libwazuhext.dll"));
    }

    /// How far a 16-byte aligned local is from 16-byte alignment, in the
    /// high half, and a + b in the low half.
    #[cfg(target_arch = "x86")]
    extern "stdcall" fn probe_stdcall(a: u32, b: u32) -> u32 {
        #[repr(align(16))]
        struct Aligned(u128);
        let local = Aligned(a as u128);
        let on_stack = std::hint::black_box(&local);
        let misalign = (on_stack as *const Aligned as usize % 16) as u32;
        misalign << 16 | (on_stack.0 as u32 + b)
    }

    #[cfg(target_arch = "x86")]
    extern "C" fn probe_cdecl(a: u32, b: u32) -> u32 {
        probe_stdcall(a, b)
    }

    /// Call `f(a, b)` with esp 4 bytes off the alignment i686 code
    /// expects, as Windows code may. Returns the result and how far esp
    /// moved over the call (8 if the callee left the arguments).
    #[cfg(target_arch = "x86")]
    fn call_misaligned(f: u32, a: u32, b: u32) -> (u32, u32) {
        let result: u32;
        let moved: u32;
        // SAFETY: f takes two 32-bit arguments. The original stack pointer
        // is kept in a slot above the arguments; edi, which callees
        // preserve, marks where the arguments start.
        unsafe {
            std::arch::asm!(
                "mov edi, esp",
                "and esp, -16",
                "push edi",
                "sub esp, 8",
                "push eax",
                "push ecx",
                "mov edi, esp",
                "call edx",
                "mov ecx, esp",
                "sub ecx, edi",
                "mov esp, [edi + 16]",
                in("edx") f,
                in("ecx") a,
                in("eax") b,
                out("edi") _,
                lateout("eax") result,
                lateout("ecx") moved,
                clobber_abi("C"),
            );
        }
        (result, moved)
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn trampoline_aligns_the_stack_for_both_conventions() {
        use crate::map::Mapped;

        // Without the trampoline the probe sees the misaligned stack, so
        // the test can tell the difference.
        let (direct, _) = call_misaligned(probe_stdcall as *const () as u32, 1, 2);
        assert_ne!(direct >> 16, 0, "direct call should be misaligned");

        let exports = [
            ("cdecl", EmuExport::Code(probe_cdecl as *const () as u32)),
            (
                "stdcall",
                EmuExport::Code(probe_stdcall as *const () as u32),
            ),
        ];
        let len = build_image("probe.dll", 0, &exports).len();
        let mapped = Mapped::anonymous(0, len).unwrap();
        let bytes = build_image("probe.dll", mapped.base(), &exports);
        let image = Image::layout("probe.dll", &bytes).unwrap();
        mapped.commit(&image).unwrap();
        let table = image.exports().unwrap().unwrap();
        let thunk = |n: &str| match table.by_name(n).unwrap().target {
            ExportTarget::Rva(rva) => mapped.base() + rva,
            ref other => panic!("{other:?}"),
        };

        assert_eq!(
            call_misaligned(thunk("stdcall"), 40, 2),
            (42, 8),
            "aligned, args popped"
        );
        assert_eq!(
            call_misaligned(thunk("cdecl"), 5, 6),
            (11, 0),
            "aligned, args left"
        );
    }
}
