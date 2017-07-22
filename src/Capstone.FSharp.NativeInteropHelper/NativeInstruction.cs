using System;
using System.Runtime.InteropServices;

namespace Capstone.FSharp.NativeInteropHelper
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct NativeInstruction {

        public uint Id;


        public ulong Address;


        public ushort Size;

        public fixed byte Bytes [16];


        public fixed byte Mnemonic [32];


        public fixed byte Operand [160];


        public IntPtr Details;

        public byte[] ManagedBytes {
            get {
                fixed (byte* pBytes = this.Bytes) {
                    var pPBytes = new IntPtr(pBytes);
                    var managedBytes = new byte[this.Size];

                    Marshal.Copy(pPBytes, managedBytes, 0, this.Size);
                    return managedBytes;
                }
            }
        }


        public string ManagedMnemonic {
            get {
                fixed (byte* pMnemonic = this.Mnemonic) {
                    return new string((sbyte*) pMnemonic);
                }
            }
        }

        public string ManagedOperand {
            get {
                fixed (byte* pOperand = this.Operand) {
                    return new string((sbyte*) pOperand);
                }
            }
        }

        /// <summary>
        ///     Get Instruction's X86 Detail.
        /// </summary>
        public NativeX86InstructionDetail NativeX86Detail
        {
            get
            {
                var pDetail = NativeMethods.cs_x86_detail(this.Details);
                return (NativeX86InstructionDetail)Marshal.PtrToStructure(pDetail, typeof(NativeX86InstructionDetail));
            }
        }
    }

}
