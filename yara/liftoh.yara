rule Liftoh : Dropper
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: a4746ecbb7dc5a9856a15ba80cc2cc3d"
        description = "https://www.secureworks.com/research/spam-campaign-delivers-liftoh-downloader"

    strings:
        $s1 = "(Decrypted Plain Text)"
        $s2 = "(Cipher Text)"
        $s3 = "Test %d: key size = %3d bits"
        $s4 = "VirtualAlloc"

    condition:
        all of them
}

rule Liftoh2 : Dropper
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-23"
        sample = "md5: a4746ecbb7dc5a9856a15ba80cc2cc3d"
        description = "https://www.secureworks.com/research/spam-campaign-delivers-liftoh-downloader"

    strings:
        $s1 = "InjectApcRoutine"
        $s2 = "explorer.exe"
        $s3 = "tid=%d&ta=%s-%x"
        $s4 = "fid=%d"
        $s5 = "os=%s&bid=%s"
        $s6 = "buildid"
        $s7 = "srvurls="
        $s8 = "srvretry="

    condition:
        4 of them
}
