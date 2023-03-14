rule rovnix_installer: bootkit
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample = "ade71bf37ff1ef296aaa22a51f2c761e"

    strings:
        $decrypted_1 = "%s\\cmd.exe /C wusa.exe %s /extract:%s\\%s" wide ascii
        $decrypted_2 = "Microsoft\\Crypto\\RSA" wide ascii
        $decrypted_3 = "svchost.exe" wide ascii
        $decrypted_4 = "sysprep.exe" wide ascii
        $decrypted_5 = "NtWow64QueryInformationProcess64" wide ascii
        $decrypted_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $decrypted_7 = "SOFTWARE\\Microsoft\\Installer\\Products" wide ascii
        $decrypted_8 = "POST %s HTTP/1.0" wide ascii
        $decrypted_9 = "win32k.sys" wide ascii
        $decrypted_10 = "Windows 8.1" wide ascii
        $decrypted_11 = "RSA1" wide ascii
        $decrypted_12 = "[VID=%u]" wide ascii
        $decrypted_13 = "checkpointsoftware" wide ascii
        $decrypted_14 = "agnitum" wide ascii
        $decrypted_15 = "deepfreeze" wide ascii
        $decrypted_16 = "AP32"
        $decrypted_17 = "aPLib v1.01  -  the smaller the better :)"

    condition:
        (10 of ($decrypted_*))
}


rule rovnix_dll: bootkit
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample32 = "284c8188657cabad50c3192200ea445a" /* 32 bit version */
		sample64 = "915d8d9d7f34808fd24a427cf22c0e93" /* 64 bit version */

    strings:
        $decrypted_1 = "abcdefghijklmnopqrstuvwxyz123456789" wide ascii
        $decrypted_2 = "PLUGIN" wide ascii
        $decrypted_3 = "DllInitialize" wide ascii
        $decrypted_4 = "SH3" wide ascii
        $decrypted_5 = "update" wide ascii
        $decrypted_6 = ".dat" wide ascii
        $decrypted_7 = "Microsoft Enhanced Cryptographic Provider v1.0" wide ascii
        $decrypted_8 = "BOOTKIT_DLL.dll" wide ascii
        $decrypted_9 = "\\\\.\\pipe\\vhost%u" wide ascii
        $decrypted_10 = "explorer.exe" wide ascii
        $decrypted_11 = "NTFS" wide ascii
        $decrypted_12 = ".cn" wide ascii
        $decrypted_13 = ".onion" wide ascii
        $decrypted_14 = "127.0.0.1" wide ascii
        $decrypted_15 = "0.lu.pool.ntp.org" wide ascii

    condition:
        (10 of ($decrypted_*))
}

rule rovnix_kernel_module_1: bootkit
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample32 = "41c462c31a08b113bc58e6adaecc86b5" /* 32 bit version */
		sample64 = "b36c1ee311a0955e6ae92014560e4315" /* 64 bit version */

    strings:
        $decrypted_1 = "LdrLoadDll" wide ascii
        $decrypted_2 = "LdrGetProcedureAddress" wide ascii
        $decrypted_3 = "NtProtectVirtualMemory" wide ascii
        $decrypted_4 = "Wow64ApcRoutine" wide ascii
        $decrypted_5 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide ascii
        $decrypted_6 = "\\Device\\Harddisk0\\DR0" wide ascii
        $decrypted_7 = "\\BOOT.SYS" wide ascii
        $decrypted_8 = "\\Callback\\PowerState" wide ascii
        $decrypted_9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\null" wide ascii
        $decrypted_10 = "\\INJECTS.SYS" wide ascii
        $decrypted_11 = "RSDS" wide ascii

    condition:
        (7 of ($decrypted_*))
}

rule rovnix_kernel_module_2: bootkit
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample32 = "2be56b2ed5ba37c6df22cf2aa13fd352" /* 32 bit version */
		sample64 = "ac95ea72a833d54be29791008f3ced14" /* 64 bit version */

    strings:
        $decrypted_1 = "Texas1" wide ascii
        $decrypted_2 = "Austin1" wide ascii
        $decrypted_3 = "OVERFLOW" wide ascii
        $decrypted_4 = "Myfault Color Switcher" wide ascii
        $decrypted_5 = "Sysinternals0" wide ascii
        $decrypted_6 = "VeriSign" wide ascii
        $decrypted_7 = "Headquarters" wide ascii
        $decrypted_8 = "Z0X03" wide ascii

    condition:
        (6 of ($decrypted_*))
}

rule rovnix_loader: bootkit
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample32 = "2be56b2ed5ba37c6df22cf2aa13fd352" /* 32 bit version */
		sample64 = "ac95ea72a833d54be29791008f3ced14" /* 64 bit version */

    strings:
        $s1 = "mividlec.com"

    condition:
        $s1
}


rule rovnix_packer: packer
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2015-06-24"
		version = "1"
		description = "Rovnix component of Avalanche infrastructure"
		sample32 = "2be56b2ed5ba37c6df22cf2aa13fd352" /* 32 bit version */
		sample64 = "ac95ea72a833d54be29791008f3ced14" /* 64 bit version */

    strings:
        $s1 = "BNAA1"
        $s2 = "LoadLibraryA"
        $s3 = "RtlExitUserThread"
        $s4 = "USER32.DLL"
        $s5 = "EnumWindows"

    condition:
        all of them
}
