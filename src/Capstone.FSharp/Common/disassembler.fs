namespace Capstone.FSharp

#nowarn "9"

open System

open Microsoft.FSharp.NativeInterop

open Capstone.FSharp
open Capstone.FSharp.NativeInterop

[<Sealed>]
type public CapstoneDisassembler (disassemblyMode: DisassemblyMode) as this = 
        
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

    let disassembleInternal address (code: nativeptr<byte>) length archCtor =
        
        let mutable insn = Unchecked.defaultof<cs_insn>
        let mutable detail = Unchecked.defaultof<cs_detail>

        if this.Details then 
            insn.Details <- NativePtr.toNativeInt &&detail

        let mutable size = unativeint length
        let mutable addr = address
        let mutable offset = code

        [| while CSInvoke.cs_disasm_iter(this.Handle, &offset, &size, &addr, NativePtr.toNativeInt &&insn) && size > 0un do
            let managedDetail = 
                if this.Details then 
                    Some (makeInstructionDetail<'Register, 'Group> (NativePtr.ofNativeInt insn.Details |> NativePtr.read) (archCtor insn))
                else None
            yield makeInstruction<'Opcode,'Register,'Group> insn managedDetail
        |]

    let disassembleManaged address (code: byte []) archCtor =
        use codePtr = fixed code
        disassembleInternal address codePtr code.Length archCtor

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
        | CapstoneError.Ok -> 
            cs_mode <- newCapstoneMode
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

    member x.Disassemble(addr: uint64, code: byte []) : Instruction<_, _, _> [] =
        match x.Mode with
        | X86Mode _ -> 
            X86.Internal.makeInstructionInfo >> X86Info
            |> disassembleManaged<X86.Opcode, X86.Register, X86.InstructionGroup> addr code
        | _ -> raise (NotImplementedException())

    member x.Disassemble(addr: uint64, code: nativeptr<byte>, length: int32) : Instruction<_, _, _> [] =
        match x.Mode with
        | X86Mode _ -> 
            X86.Internal.makeInstructionInfo >> X86Info
            |> disassembleInternal<X86.Opcode, X86.Register, X86.InstructionGroup> addr code length
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