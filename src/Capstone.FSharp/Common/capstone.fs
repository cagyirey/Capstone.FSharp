namespace Capstone.FSharp

open Capstone.FSharp.NativeInterop
open Capstone.FSharp.NativeInterop.Disassembler

open System.Runtime.InteropServices

open FSharp.NativeInterop

#nowarn "9"

//[<AutoOpen>]
module Disassembler = 
    open System

    /// Indicates the compiled version of capstone.dll
    let BindingsVersion =
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
    
    type ArchitectureSpecificInstructionInfo = 
        | DetailsUnavailable
        | X86Info of X86.InstructionInfo
        | ArmInfo
        | MipsInfo
        | PowerPCInfo
        | Arm64Info
    
    type InstructionDetails<'Register, 'Group when 'Register: enum<int32> and 'Group: enum<int32>> = 
        { ImplicitReads: 'Register array
          ImplicitWrites: 'Register array
          Groups: 'Group array
          ArchitectureSpecificDetails: ArchitectureSpecificInstructionInfo }
    
    let private makeInstructionDetail<'Register, 'Group when 'Register: enum<int32> and 'Group: enum<int32>> (cs_detail: cs_detail) cs_arch = 
        { ImplicitReads = 
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
    
    let private makeInstruction<'Opcode, 'Register, 'Group when 'Opcode: enum<int32> and 'Register: enum<int32> and 'Group: enum<int32>> (cs_insn: cs_insn) (detail: InstructionDetails<'Register, 'Group> option) = 
         { Opcode = LanguagePrimitives.EnumOfValue<int32, 'Opcode>(int32 cs_insn.Id)
           Address = cs_insn.Address
           Assembly = cs_insn.ManagedBytes
           Mnemonic = cs_insn.ManagedMnemonic
           Operands = cs_insn.ManagedOperand
           Details = detail }
    
    let private getEndianMode = 
        function 
        | LittleEndian -> Mode.LittleEndian
        | BigEndian -> Mode.BigEndian
    
    let private getMipsVariant = 
        function 
        | Some N64 -> Mode.N64
        | Some MicroMips -> Mode.Micro
        | None -> Mode.Default
    
    let private capstoneMode = function 
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
        
    let private disassembleInternal<'Opcode, 'Register, 'Group when 'Opcode: enum<int32> and 'Register: enum<int32> and 'Group: enum<int32>> addr (code: byte[]) csh details (archCtor: _ -> ArchitectureSpecificInstructionInfo) =
        use codePtr = fixed code
        
        let mutable insn = Unchecked.defaultof<cs_insn>
        let mutable detail = Unchecked.defaultof<cs_detail>

        if details then 
            insn.Details <- NativePtr.toNativeInt &&detail

        let mutable size = unativeint code.Length
        let mutable addr = addr
        let mutable offset = codePtr 

        [| while CSInvoke.cs_disasm_iter(csh, &offset, &size, &addr, NativePtr.toNativeInt &&insn) && size > 0un do
            let managedDetail = 
                if details then 
                    Some (makeInstructionDetail<'Register, 'Group> (NativePtr.ofNativeInt insn.Details |> NativePtr.read) (archCtor insn))
                else None
            let instruction = makeInstruction<'Opcode,'Register,'Group> insn managedDetail
            yield instruction |]
    
    [<Sealed>]
    type public CapstoneDisassembler (disassemblyMode: DisassemblyMode) = 
        
        // TODO: check capstone.dll for enabled architectures
        let arch = 
            match disassemblyMode with
            | X86Mode _ -> Architecture.X86 
            | _ -> raise (NotSupportedException("Parameter `disassemblyMode` must be an instance of X86Mode"))
          //| ArmMode _ -> Architecture.Arm
          //| MipsMode _ -> Architecture.Mips
          //| PowerPCMode _ -> Architecture.PowerPC
          //| Arm64Mode -> Architecture.Arm64
        
        let mutable mode = disassemblyMode
        let mutable cs_mode = capstoneMode disassemblyMode
        let mutable handle = UIntPtr.Zero
        let mutable details = false

        let mutable syntax = 
            match arch with
            | Architecture.X86 -> Some <| X86Syntax Intel
            | Architecture.PowerPC -> Some <| PowerPCSyntax Standard
            | _ -> None
        
        let setDetails enabled = 
            match CSInvoke.cs_option(handle, CapstoneOptionKind.Details, unativeint(if enabled then CapstoneOptionValue.On else CapstoneOptionValue.Off)) with
            | CapstoneError.Ok -> details <- enabled
            | error -> raise (new CapstoneException(error))
        
        // Arm and Mips may change between Arm and Thumb, Mips32 and Mips64 modes respectively at runtime
        let setMode newMode = 
            let newCapstoneMode = capstoneMode newMode
            match CSInvoke.cs_option(handle, CapstoneOptionKind.Mode, unativeint newCapstoneMode) with
            | CapstoneError.Ok -> cs_mode <- newCapstoneMode
                                  mode <- newMode
            | error -> raise (new CapstoneException(error))
        
        let setX86Syntax _syntax = 
            match CSInvoke.cs_option(handle, CapstoneOptionKind.Syntax, unativeint(if _syntax = X86Syntax.Intel then CapstoneOptionValue.IntelSyntax else CapstoneOptionValue.ATTSyntax)) with
            | CapstoneError.Ok -> syntax <- Some(X86Syntax _syntax)
            | error -> raise (new CapstoneException(error))
        
        let setPowerPCSyntax _syntax = 
            match CSInvoke.cs_option(handle, CapstoneOptionKind.Syntax, unativeint(if _syntax = PowerPCSyntax.Standard then CapstoneOptionValue.DefaultSyntax else CapstoneOptionValue.PowerPCShortRegisters)) with
            | CapstoneError.Ok -> syntax <- Some(PowerPCSyntax _syntax)
            | error -> raise (new CapstoneException(error))
        
        do 
            match CSInvoke.cs_open(arch, cs_mode, &handle) with
            | CapstoneError.Ok -> ()
            | error -> raise (new CapstoneException(error))

        member x.Handle 
            with internal get () = handle

        member internal x.Architecture = arch

        member x.Disassemble(addr, code: byte []) : Instruction<_, _, _> [] =
            match x.Mode with
            | X86Mode _ -> 
                X86.Internal.makeInstructionInfo >> X86Info
                |> disassembleInternal<X86.Opcode, X86.Register, X86.InstructionGroup> addr code x.Handle x.Details
            | _ -> raise (NotImplementedException())

        member x.Mode
            with get () = mode
            and set (value) = 
                match mode, value with
                | ArmMode _, ArmMode _ 
                | MipsMode _, MipsMode _ -> setMode value
                | ArmMode _, _ 
                | MipsMode _, _ -> raise <| new CapstoneException(CapstoneError.InvalidMode)
                | _ -> raise (new CapstoneException("The current architecute does not support changing modes at runtime."))
        
        member x.Details 
            with get () = details
            and set (value) = 
                match value with
                | true when not details -> setDetails true
                | false when details -> setDetails false
                | _ -> ()
        
        member x.Syntax 
            with get () = syntax
            and set (value: AssemblySyntax option) = 
                match value with
                | Some(X86Syntax syn) when x.Architecture = Architecture.X86 -> setX86Syntax syn
                | Some(PowerPCSyntax syn) when x.Architecture = Architecture.PowerPC -> setPowerPCSyntax syn
                | None when x.Architecture = Architecture.X86 || x.Architecture = Architecture.PowerPC -> 
                    invalidArg "value" "The current architecture does not support the supplied syntax option."
                | None -> ()
                | _ -> invalidArg "value" "The current architecture does not support the supplied syntax option."
        
        override x.Finalize() = (x :> IDisposable).Dispose()

        interface IDisposable with

            member x.Dispose() = 
                if handle <> UIntPtr.Zero then 
                    GC.SuppressFinalize x
                    match CSInvoke.cs_close(&handle) with
                    | CapstoneError.Ok -> ()
                    | error -> raise (new CapstoneException(error))