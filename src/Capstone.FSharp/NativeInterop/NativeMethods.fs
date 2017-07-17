namespace Capstone.FSharp

open System
open System.Runtime.InteropServices

open Capstone.FSharp.NativeInterop.Disassembler

module (*internal *) CSInvoke = 

    
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern CapstoneError cs_open(Architecture arch, Mode mode, unativeint& csh)
    
    //size_t CAPSTONE_API cs_disasm(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern UIntPtr cs_disasm(unativeint csh, byte[] code, unativeint size, uint64 address, unativeint count, unativeint& insn)

    // bool CAPSTONE_API cs_disasm_iter(csh ud, const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn)
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern bool cs_disasm_iter(unativeint csh, uint8* & code, unativeint& size, uint64& address, void* insn)

    // cs_insn * CAPSTONE_API cs_malloc(csh ud)
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern void* cs_malloc(unativeint csh)

    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern bool cs_support(Architecture arch)
    
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern String cs_strerror(CapstoneError error)
    
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern void cs_free(nativeint insn, unativeint count)
    
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern CapstoneError cs_close(unativeint& csh)
    
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern CapstoneError cs_option(unativeint csh, CapstoneOptionKind opt, unativeint value)
        
    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern CapstoneError cs_errno(unativeint csh)

    [<DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)>]
    extern int cs_version(int& major, int& minor)