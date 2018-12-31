namespace Capstone.FSharp.Tests

#nowarn "58"

open NUnit.Framework
open FsUnit

open Capstone.FSharp
open Capstone.FSharp.Disassembler

[<TestFixture>]
module ``Core disassembler tests`` =

    [<Test>]
    let ``Can instantiate a new disassembler`` () =
        use disassembler = new CapstoneDisassembler(X86Mode X86_32)
        disassembler |> should be instanceOfType<CapstoneDisassembler>

    [<Test>]
    let ``Can enable detail disassembly`` () =
        use disassembler = new CapstoneDisassembler(X86Mode X86_32)
        disassembler.Details |> should equal false
        disassembler.Details <- true
        disassembler.Details |> should equal true

    [<Test>]
    let ``Can toggle SKIPDATA mode`` () =
        use disassembler = new CapstoneDisassembler(X86Mode X86_32)
        disassembler.SkipData |> should equal false
        disassembler.SkipData <- true
        disassembler.SkipData |> should equal true
        
    [<Test>]
    let ``Can toggle disassembly syntax`` () =
        let intel, att = Some (X86Syntax Intel), Some (X86Syntax ATT)
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, Syntax=intel)
        disassembler.Syntax |> should equal intel
        disassembler.Syntax <- att
        disassembler.Syntax |> should equal att

    [<Test>]
    let ``Can disassemble basic x86 instructions`` () =
        let codeBytes = "\x6A\xFF\x68\x9B\x6C\x74\x01\x64\xA1\x00\x00\x00\x00"B
        let disassembly : X86Instruction [] = [| 
            { 
                Opcode = X86.Opcode.PUSH
                Address = 4096UL
                Assembly = [|106uy; 255uy|]
                Mnemonic = "push"
                Operands = "-1" 
                Details = None }
            { 
                Opcode = X86.Opcode.PUSH
                Address = 4098UL
                Assembly = [|104uy; 155uy; 108uy; 116uy; 1uy|]
                Mnemonic = "push"
                Operands = "0x1746c9b"
                Details = None }
            {
                Opcode = X86.Opcode.MOV;
                Address = 4103UL;
                Assembly = [|100uy; 161uy; 0uy; 0uy; 0uy; 0uy;|];
                Mnemonic = "mov";
                Operands = "eax, dword ptr fs:[0]";
                Details = None } |]

        use disassembler = new CapstoneDisassembler(X86Mode X86_32)
        disassembler.Disassemble(0x1000UL, codeBytes)
        |> should equal disassembly
 
    [<Test>]
    let ``Can skip inline data`` () =
        let codeBytes = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"B
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, SkipData=true)

        disassembler.Disassemble(0x1000UL, codeBytes)
        |> should haveLength 6

    // Requires ARM support
    //[<Test>]
    //let ``Can dynamically toggle disassembly mode`` () = 
    //    use disassembler = new CapstoneDisassembler(ArmMode Arm, false)
    //    disassembler.Mode |> should equal (ArmMode Arm)
    //    disassembler.Mode <- ArmMode Thumb
    //    disassembler.Mode |> should equal (ArmMode Thumb)

[<TestFixture>]
module ``X86 disassembly tests`` =

    open Capstone.FSharp.X86

    let movInstruction : X86Instruction = {
        Opcode = Opcode.MOV;
        Address = 4096UL;
        Assembly = [|100uy; 161uy; 0uy; 0uy; 0uy; 0uy|];
        Mnemonic = "mov";
        Operands = "eax, dword ptr fs:[0]";
        Details = Some {
            ImplicitReads = [||];
            ImplicitWrites = [||];
            Groups = [|InstructionGroup.MODE32|];
            ArchitectureSpecificDetails =
            X86Info {
                Prefix = [|0uy; 0uy; 0uy; 0uy|];
                REXPrefix = 0uy;
                Opcode = [|161uy; 0uy; 0uy; 0uy|];
                SIB = 0uy;
                ModRM = 0uy;
                SSECodeCondition = SSEConditionCode.None;
                AVXCodeCondition = AVXConditionCode.None;
                AVXRoundingMode = AVXRoundingMode.None;
                AVXSupressAllException = false;
                Operands = [|{
                    Value = Operand.Register Register.EAX;
                    Size = 4uy;
                    AVXBroadcast = AVXBroadcastKind.None;
                    AVXZeroOpmask = false;};
                    {Value = Memory {
                        Segment = Register.FS;
                        SIB = {
                            Scale = 1;
                            Index = Register.None;
                            Base = Register.None;};
                        Displacement = 0L;};
                        Size = 4uy;
                        AVXBroadcast = AVXBroadcastKind.None;
                        AVXZeroOpmask = false;}|];};};};

    [<Test>]
    let ``Can disassemble X86 instruction details`` () =
        let codeBytes = "\x64\xA1\x00\x00\x00\x00\x00"B
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, Details=true)

        disassembler.Disassemble(0x1000UL, codeBytes)
        |> should equal [|movInstruction|]

            

