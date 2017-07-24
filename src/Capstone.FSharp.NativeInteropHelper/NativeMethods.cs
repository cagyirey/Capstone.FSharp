using System;
using System.Runtime.InteropServices;

namespace Capstone.FSharp.NativeInteropHelper
{
    internal static class NativeMethods
    {
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cs_arm_detail(IntPtr pDetail);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cs_arm64_detail(IntPtr pDetail);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cs_x86_detail(IntPtr pDetail);
    }
}

