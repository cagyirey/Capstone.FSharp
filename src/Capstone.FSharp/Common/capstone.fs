namespace Capstone.FSharp

open System

open Capstone.FSharp.NativeInterop

[<AutoOpen>]
module Disassembler = 

    /// Indicates the compiled version of capstone.dll
    let CapstoneVersion =
        let mutable major, minor = 0, 0
        do CSInvoke.cs_version(&major, &minor) |> ignore
        Version(major, minor)

    [<Sealed>]
    type CapstoneException internal (message) = 
        inherit Exception(message)
        internal new() = new CapstoneException("")
        internal new(error: CapstoneError) = new CapstoneException(CSInvoke.cs_strerror error)

    type X86Syntax = 
        | Intel
        | ATT
    
    type PowerPCSyntax = 
        | Standard
        | ShortRegisters
    
    type AssemblySyntax = 
        | X86Syntax of X86Syntax
        | PowerPCSyntax of PowerPCSyntax
    
    type X86Mode = 
        | X86_16
        | X86_32
        | X86_64
    
    type ArmMode = 
        | Arm
        | Thumb
    
    type MipsMode = 
        | Mips32
        | Mips64
    
    type MipsVariant = 
        | N64
        | MicroMips
    
    type PowerPCMode = 
        | PowerPC32
        | PowerPC64
    
    type PlatformEndianness = 
        | BigEndian
        | LittleEndian
    
    type DisassemblyMode = 
        | X86Mode of X86Mode
        | ArmMode of ArmMode
        | MipsMode of MipsMode * MipsVariant option * PlatformEndianness
        | PowerPCMode of PowerPCMode * PlatformEndianness
        | Arm64Mode
        | SparcMode
        | XCodeMode
        | SystemZMode
        | DetailsUnavailable

    type ArchitectureSpecificInstructionInfo = 
        | X86Info of X86.InstructionInfo
        | ArmInfo
        | MipsInfo
        | PowerPCInfo
        | Arm64Info
    
    type InstructionDetails<'Register, 'Group when 'Register: enum<int32> and 'Group: enum<int32>> = {
        ImplicitReads: 'Register array
        ImplicitWrites: 'Register array
        Groups: 'Group array
        ArchitectureSpecificDetails: ArchitectureSpecificInstructionInfo }
    
    let internal makeInstructionDetail<'Register, 'Group when 'Register: enum<int32> and 'Group: enum<int32>> (cs_detail: cs_detail) cs_arch = {
        ImplicitReads = 
            cs_detail.ManagedReadRegisters
            |> Array.map(fun reg -> LanguagePrimitives.EnumOfValue<int32, 'Register>(int32 reg))
        ImplicitWrites = 
            cs_detail.ManagedWrittenRegisters
            |> Array.map(fun reg -> LanguagePrimitives.EnumOfValue<int32, 'Register>(int32 reg))
        Groups = 
            cs_detail.ManagedGroups
            |> Array.map(fun group -> LanguagePrimitives.EnumOfValue<int32, 'Group>(int32 group))
        ArchitectureSpecificDetails = cs_arch }
    
    type Instruction<'Opcode, 'Register, 'Group when 'Opcode: enum<int32> and 'Register: enum<int32> and 'Group: enum<int32>> = 
        { Opcode: 'Opcode
          Address: uint64
          Assembly: uint8 array
          Mnemonic: string
          Operands: string
          Details: InstructionDetails<'Register, 'Group> option }

    type X86Instruction = Instruction<X86.Opcode, X86.Register, X86.InstructionGroup>

    type ArmInstruction = Instruction<ARM.Opcode, ARM.Register, ARM.InstructionGroup>
    
    let internal makeInstruction<'Opcode, 'Register, 'Group when 'Opcode: enum<int32> and 'Register: enum<int32> and 'Group: enum<int32>> (cs_insn: cs_insn) (detail: InstructionDetails<'Register, 'Group> option) = 
         { Opcode = LanguagePrimitives.EnumOfValue<int32, 'Opcode>(int32 cs_insn.Id)
           Address = cs_insn.Address
           Assembly = cs_insn.ManagedBytes
           Mnemonic = cs_insn.ManagedMnemonic
           Operands = cs_insn.ManagedOperand
           Details = detail }
    
    let internal getEndianMode = 
        function 
        | LittleEndian -> Mode.LittleEndian
        | BigEndian -> Mode.BigEndian
    
    let internal getMipsVariant = 
        function 
        | Some N64 -> Mode.N64
        | Some MicroMips -> Mode.Micro
        | None -> Mode.Default
    
    let internal capstoneMode = function 
    | X86Mode mode -> 
        match mode with
        | X86_16 -> Mode.Mode16
        | X86_32 -> Mode.Mode32
        | X86_64 -> Mode.Mode64
    | ArmMode mode -> 
        match mode with
        | Arm -> Mode.Arm
        | Thumb -> Mode.Thumb
    | MipsMode(mode, variant, endian) -> 
        match mode  with
        | Mips32 -> Mode.Mode32 ||| getMipsVariant variant ||| getEndianMode endian
        | Mips64 -> Mode.Mode64 ||| getMipsVariant variant ||| getEndianMode endian
    | PowerPCMode(mode, endian) -> 
        match mode with
        | PowerPC32 -> Mode.Mode32 ||| getEndianMode endian
        | PowerPC64 -> Mode.Mode64 ||| getEndianMode endian
    | Arm64Mode -> Mode.Arm
    | SparcMode -> Mode.SparcV9
    