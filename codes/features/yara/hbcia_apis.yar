rule hbcia_APIs {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects common HBCIA APIs."
    strings:
        $a1 = "Process32First"
        $a2 = "Process32Next"
        $a3 = "CreateToolhelp32Snapshot"
        $a4 = "NtQueryInformationThread"
        $a5 = "OpenThread"
        $a6 = "NtCreateThreadEx"
        $a7 = "ResumeThread"
        $a8 = "WriteProcessMemory"
        $a9 = "ReadProcessMemory"
        $a10 = "CreateRemoteThread"
        $a11 = "OpenProcess"
        $a12 = "SetThreadContext"
        $a13 = "NtQueueApcThread"
        $a14 = "NtResumeThread"
        $a15 = "SuspendThread"
        $a16 = "UnmapViewOfFile"
        $a17 = "VirtualAllocEx"
        $a18 = "NtReadVirtualMemory"
        $a19 = "ZwResumeThread"
        $a20 = "ZwUnmapViewOfSection"
        $a21 = "ZwMapViewOfSection"
        $a22 = "ZwOpenProcess"
        $a23 = "ZwGetContextThread"
        $a24 = "ZwSetContextThread"
        $a25 = "ZwQueueApcThread"
        $a26 = "QueueUserAPC"
    condition:
        5 of ($a*)
}