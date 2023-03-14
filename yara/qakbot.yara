rule Qakbot : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 9818492c93d49694d3ee48604c449ae6"

    strings:
        $s1 = "\\\\.\\pipe\\%ssp"
        $s2 = "*.sol"
        $s3 = "webinjects.cb"
        $s4 = "set_url"
        $s5 = "#SharedObjects"
        $s6 = "macromedia.com"
        $s7 = "a=%s&b="
        $s8 = "%s\\~%s.tmp"
        $s9 = "http://ftp.gnu.org/gnu/glibc/glibc-2.0.1.tar.gz"

    condition:
        all of them
}

rule Qakbot_banker : Banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 9818492c93d49694d3ee48604c449ae6"

    strings:
        $s1 = "cashmanageronline.bbt.com"
        $s2 =  "Norton"

    condition:
        all of them
}

rule Qakbot_unpacker : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 9818492c93d49694d3ee48604c449ae6"

    strings:
        $s1 = "ieemsd.dll"
        $s2 = "PADPADDINGXX"
        $s3 = "IsWow64Process"
        $s4 = "SeDebugPrivilege"
        $s5 = "user32.dll"
        $s6 = "d.exe"

    condition:
        all of them
}