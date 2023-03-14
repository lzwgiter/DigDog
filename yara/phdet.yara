rule Phdet : DDoS
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: ac2d7f21c826ce0c449481f79138aebd"
        description = "https://securelist.com/blog/research/73440/blackenergy-apt-attacks-in-ukraine-employ-spearphishing-with-word-documents/"

    strings:
        $s1 = "AirpcapGetMacAddress"
        $s2 = "packet.dll"
        $s3 = "\\Device\\NPF_"
        $s4 = "Microsoft Visual C++ Runtime Library"

    condition:
        all of them
}

rule Phdet2 : DDoS
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-23"
        sample = "md5: ac2d7f21c826ce0c449481f79138aebd"
        description = "https://securelist.com/blog/research/73440/blackenergy-apt-attacks-in-ukraine-employ-spearphishing-with-word-documents/"

    strings:
        $s1 = "b_id=%s&b_gen=%s&b_ver=%s&os_v=%s&os_type=%"
        $s2 = "b_gen="
        $s3 = "os_type="
        $s4 = "body="
        $s5 = "Microsoft Enhanced Cryptographic Provider v1.0"
        $s6 = "WinSta0"

    condition:
        4 of them
}
