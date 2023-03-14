rule Gookit : banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "DLL injection. See http://blog.cert.societegenerale.com/2015/04/analyzing-gootkits-persistence-mechanism.html"
        sample = "md5: ebe4babd813271e3c93906c4244d2140"

    strings:
         $s1 = "STATIC"
         $s2 = "URLOpenBlockingStreamW"
         $s3 = "win32k.sys"
         $s4 = "RtlQueryEnvironmentVariable_U"

    condition:
        all of them
}