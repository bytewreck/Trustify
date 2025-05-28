using System;
using System.Runtime.InteropServices;

namespace Trustify
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_AUTH_INFORMATION
        {
            public long LastUpdateTime;
            public uint AuthType;
            public uint AuthInfoLength;
            public IntPtr AuthInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TRUSTED_DOMAIN_AUTH_INFORMATION
        {
            public uint IncomingAuthInfos;
            public IntPtr IncomingAuthenticationInformation;
            public IntPtr IncomingPreviousAuthenticationInformation;
            public uint OutgoingAuthInfos;
            public IntPtr OutgoingAuthenticationInformation;
            public IntPtr OutgoingPreviousAuthenticationInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TRUSTED_DOMAIN_INFORMATION_EX
        {
            public UNICODE_STRING Name;
            public UNICODE_STRING FlatName;
            public IntPtr Sid;
            public uint TrustDirection;
            public uint TrustType;
            public uint TrustAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_FOREST_TRUST_DOMAIN_INFO
        {
            public IntPtr Sid;
            public UNICODE_STRING DnsName;
            public UNICODE_STRING NetbiosName;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_FOREST_TRUST_SCANNER_INFO
        {
            public IntPtr DomainSid;
            public UNICODE_STRING DnsName;
            public UNICODE_STRING NetbiosName;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_FOREST_TRUST_BINARY_DATA
        {
            public uint Length;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct LSA_FOREST_TRUST_RECORD2
        {
            [FieldOffset(0)]
            public uint Flags;

            [FieldOffset(4)]
            public uint ForestTrustType;

            [FieldOffset(8)]
            public long Time;

            [FieldOffset(16)]
            public UNICODE_STRING TopLevelName;

            [FieldOffset(16)]
            public LSA_FOREST_TRUST_DOMAIN_INFO DomainInfo;

            [FieldOffset(16)]
            public LSA_FOREST_TRUST_BINARY_DATA BinaryData;

            [FieldOffset(16)]
            public LSA_FOREST_TRUST_SCANNER_INFO ScannerInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_FOREST_TRUST_INFORMATION2
        {
            public uint RecordCount;
            public IntPtr Entries;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int LsaOpenPolicy(UNICODE_STRING SystemName, LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int LsaCreateTrustedDomainEx(IntPtr PolicyHandle, TRUSTED_DOMAIN_INFORMATION_EX TrustedDomainInformation,
            TRUSTED_DOMAIN_AUTH_INFORMATION AuthenticationInformation, uint DesiredAccess, out IntPtr TrustedDomainHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int LsaDeleteTrustedDomain(IntPtr ObjectHandle, IntPtr TrustedDomainSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int LsaSetForestTrustInformation2(IntPtr PolicyHandle, UNICODE_STRING TrustedDomainName, int HighestRecordType,
            LSA_FOREST_TRUST_INFORMATION2 ForestTrustInfo, [MarshalAs(UnmanagedType.Bool)] bool CheckOnly, out IntPtr CollisionInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemTime(out long SystemTime);

        static int OpenPolicyHandle(string system_name, out IntPtr policy_handle)
        {
            var SystemName = new UNICODE_STRING(system_name);
            var Attributes = new LSA_OBJECT_ATTRIBUTES()
            {
                RootDirectory = IntPtr.Zero
            };

            return LsaOpenPolicy(SystemName, Attributes, 0x02000000 /* MAXIMUM_ALLOWED */, out policy_handle);
        }

        static int ClosePolicyHandle(IntPtr policy_handle)
        {
            return LsaClose(policy_handle);
        }

        static int CreateDomainTrust(IntPtr policy_handle, string dns_name, string netbios_name, string sid, string trust_password)
        {
            var trusted_domain_info = new TRUSTED_DOMAIN_INFORMATION_EX()
            {
                Name = new UNICODE_STRING(dns_name),
                FlatName = new UNICODE_STRING(netbios_name),
                TrustDirection = 0x00000001, // TRUST_DIRECTION_INBOUND
                TrustType = 0x00000002, // TRUST_TYPE_UPLEVEL
                TrustAttributes = 0x00000008 | 0x00000800 // TRUST_ATTRIBUTE_FOREST_TRANSITIVE | TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
            };

            if (!ConvertStringSidToSid(sid, out trusted_domain_info.Sid))
                return unchecked((int)0xC000000D);

            try
            {
                var auth_info = new LSA_AUTH_INFORMATION()
                {
                    AuthType = 2, // A plaintext password. Indicates that the information stored in the attribute is a Unicode plaintext password. If this AuthType is present, Kerberos can then use this password to derive additional key types that are needed to encrypt and decrypt cross-realm TGTs.
                    AuthInfoLength = (uint)(trust_password.Length * 2),
                    AuthInfo = Marshal.StringToHGlobalUni(trust_password)
                };

                if (NtQuerySystemTime(out auth_info.LastUpdateTime) < 0)
                    return unchecked((int)0xC000000D);

                var auth_info_ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_AUTH_INFORMATION)));
                Marshal.StructureToPtr(auth_info, auth_info_ptr, false);

                var trusted_domain_auth_info = new TRUSTED_DOMAIN_AUTH_INFORMATION()
                {
                    IncomingAuthInfos = 1,
                    IncomingAuthenticationInformation = auth_info_ptr
                };

                var trusted_domain = IntPtr.Zero;

                try
                {
                    return LsaCreateTrustedDomainEx(policy_handle, trusted_domain_info, trusted_domain_auth_info, 0x02000000 /* MAXIMUM_ALLOWED */, out trusted_domain);
                }
                finally
                {
                    if (trusted_domain != IntPtr.Zero)
                        LsaClose(trusted_domain);

                    if (auth_info_ptr != IntPtr.Zero)
                        Marshal.FreeHGlobal(auth_info_ptr);
                }
            }
            finally
            {
                if (trusted_domain_info.Sid != IntPtr.Zero)
                    LocalFree(trusted_domain_info.Sid);
            }
        }

        static int DeleteDomainTrust(IntPtr policy_handle, string sid)
        {
            if (!ConvertStringSidToSid(sid, out IntPtr trusted_domain_sid))
                return unchecked((int)0xC000000D);

            try
            {
                return LsaDeleteTrustedDomain(policy_handle, trusted_domain_sid);
            }
            finally
            {
                if (trusted_domain_sid != IntPtr.Zero)
                    LocalFree(trusted_domain_sid);
            }
        }

        static int SetDomainTrust(IntPtr policy_handle, string dns_name)
        {
            var trusted_domain_name = new UNICODE_STRING(dns_name);
            var forest_trust_record = new LSA_FOREST_TRUST_RECORD2()
            {
                Flags = 0,
                ForestTrustType = 0, // ForestTrustTopLevelName
                TopLevelName = new UNICODE_STRING(dns_name)
            };

            if (NtQuerySystemTime(out forest_trust_record.Time) < 0)
                return unchecked((int)0xC000000D);

            IntPtr forest_trust_record_ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_RECORD2)));
            Marshal.StructureToPtr(forest_trust_record, forest_trust_record_ptr, false);

            try
            {
                GCHandle gch = GCHandle.Alloc(forest_trust_record_ptr, GCHandleType.Pinned);

                var forest_trust_info = new LSA_FOREST_TRUST_INFORMATION2()
                {
                    RecordCount = 1,
                    Entries = gch.AddrOfPinnedObject()
                };

                try
                {
                    return LsaSetForestTrustInformation2(policy_handle, trusted_domain_name, 2 /* ForestTrustDomainInfo */, forest_trust_info, false, out IntPtr collision_info);
                }
                finally
                {
                    if (gch != null)
                        gch.Free();
                }
            }
            finally
            {
                if (forest_trust_record_ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(forest_trust_record_ptr);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} [create|delete]");
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine($"Usage example: {AppDomain.CurrentDomain.FriendlyName} create [target] [sid] [dns] [netbios] [password]");
                Console.WriteLine($"Usage example: {AppDomain.CurrentDomain.FriendlyName} delete [target] [sid]");
            }
            else
            {
                Console.WriteLine($"{"Open",-10}: {OpenPolicyHandle("localhost", out IntPtr policy_handle)}");

                if (args[0].StartsWith("c", StringComparison.InvariantCultureIgnoreCase))
                {
                    Console.WriteLine($"{"Create",-10}: {CreateDomainTrust(policy_handle, args[3], args[4], args[2], args[5])}");
                    Console.WriteLine($"{"Set",-10}: {SetDomainTrust(policy_handle, args[3])}");
                }
                else if (args[0].StartsWith("d", StringComparison.InvariantCultureIgnoreCase))
                {
                    Console.WriteLine($"{"Delete",-10}: {DeleteDomainTrust(policy_handle, args[2])}");
                }

                Console.WriteLine($"{"Close",-10}: {ClosePolicyHandle(policy_handle)}");
            }
        }
    }
}
