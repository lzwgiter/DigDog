rule escalate_priv {
    meta:
        author = "flo@t"
        description = "Escalade priviledges"
	version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $d2 = "NtDll.dll" nocase
        $c1 = "SeDebugPrivilege"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "SeShutdownPrivilege"
        $c4 = "AdjustTokenPrivilegeValueA"
        $c5 = "privilegeWithdrawn"
        $c6 = "RtlAdjustPrivilege"
        $c7 = "LookupPrivilegeValueA"
        $c8 = "djustTokenPrivileges"
        $c9 = "EnableSpecificPrivilege"
    condition:
        1 of ($d*) and 1 of ($c*)
}