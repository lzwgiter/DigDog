rule lusypos : POS
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "DLL loading. See http://securitykitten.github.io/lusypos-and-tor/"
        sample = "md5: bc7bf2584e3b039155265642268c94c7 "

    strings:
         $s1 = "Digitb00"
         $s2 = "response"
         $s3 = "RtlDecompressBuffer"
         $s4 = "Port number too large"

    condition:
        all of them
}