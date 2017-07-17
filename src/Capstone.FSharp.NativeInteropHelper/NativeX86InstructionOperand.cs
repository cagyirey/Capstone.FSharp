using System.Runtime.InteropServices;

namespace Capstone.FSharp.NativeInteropHelper
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeX86InstructionOperand
    {
        /// <summary>
        ///     Operand's Type.
        /// </summary>
        public int Type;

        /// <summary>
        ///     Operand's Value.
        /// </summary>
        public NativeX86InstructionOperandValue Value;

        /// <summary>
        ///     Operand's Size.
        /// </summary>
        public byte Size;

        /// <summary>
        ///     Operand's AVX Broadcast.
        /// </summary>
        public int AvxBroadcast;

        /// <summary>
        ///     Operand's AVX Zero Operation Mask Flag.
        /// </summary>
        [MarshalAs(UnmanagedType.I1)]
        public bool AvxZeroOperationMask;

    }
}
