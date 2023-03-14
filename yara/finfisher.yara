rule Finfisher1 : APT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://www.codeandsec.com/FinFisher-Malware-Analysis-Part-3"
        sample = "md5: 074919F13D07CD6CE92BB0738971AFC7 "

    strings:
         $s1 = "!This program cannot be run in DOS mode."
         $s2 = "GdipDisposeImage"
         $s3 = "GdipSaveImageToFile"
         $s4 = "GdipGetImageEncodersSize"
         $s5 = "GdipGetImageEncoders"
         $s6 = "GdipCreateBitmapFromHBITMAP"
         $s7 = "GdiplusShutdown"
         $s8 = "GdiplusStartup"
         $s9 = "NtConnectPort"
         $s10 = "NtRequestWaitReplyPort"
         $s11 = "CreateRemoteThread"
         $s12 = ".dll"


    condition:
        all of them
}

rule Finfisher2 : APT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://www.codeandsec.com/FinFisher-Malware-Analysis-Part-3"
        sample = "md5: 074919F13D07CD6CE92BB0738971AFC7 "

    strings:
         $s1 = "!This program cannot be run in DOS mode."
         $s2 = "_XcptFilter"
        $s3 = "malloc"
        $s4 = "free"
        $s5 = "_initterm"
        $s6 = "_amsg_exit"
        $s7 = "_adjust_fdiv"
        $s8 = "msvcrt.dll"
        $s9 = "RtlUnwind"
        $s10 = "ntdll.dll"
        $s11 = "CloseHandle"
        $s12 = "Sleep"
        $s13 = "ExitProcess"
        $s14 = "WaitForSingleObject"
        $s15 = "ResetEvent"
        $s16 = "ReleaseMutex"
        $s17 = "SetEvent"
        $s18 = "SleepEx"
        $s19 = "GetTickCount"
        $s20 = "VirtualProtect"
        $s21 = "GetModuleHandleW"


    condition:
        all of them
}