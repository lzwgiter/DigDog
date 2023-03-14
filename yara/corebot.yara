rule Corebot : Banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 0d0d7f6f2189f000250ac92c4c6f7dc3"
        description = "https://securityintelligence.com/watch-out-for-corebot-new-stealer-in-the-wild/"

    strings:
        $s1 = "plugin.is_safe"
        $s2 = "plugin.version"
        $s3 = "echoooou!!!!!!!!11111111111111111"
        $s4 = "core.dga"

    condition:
        all of them
}
