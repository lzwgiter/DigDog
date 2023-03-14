rule Dorv : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 6e4264ee1d45db83765036f881f5fec4"

    strings:
        $s1 = "Opera/9.00 (Windows NT 5.1; U; en)"
        $s2 = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)"
        $s3 = "-Media-Player/10.00.00.3990; InfoPath.2"
        $s4 = "JOIN"
        $s5 = "PRIVMSG"
        $s6 = "--%08x-%04x-%04x-%04x%04x"
        $s7 = "POST"
        $s8 = "RunAsInvoker"
        $s9 = "%s=%u&%s=%s"

    condition:
        all of them
}
