rule Sphinx : banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-17"
        description = "See https://securityintelligence.com/brazil-cant-catch-a-break-after-panda-comes-the-sphinx/"
        sample = "md5: 03915a1f03df164f48ac4dfd04d9c2c4"

    strings:
         $s1 = "Stack part of OpenSSL 1.0.1p 9 Jul 2015"
         $s2 = "14.10.2016"
         $s3 = "__injectEntryForThreadEntry"
         $s4 = "MKCALENDAR"
         $s5 = "publicKey"
         $s6 = "@GetQueueStatus"
         $s7 = "openssl-dist-1.0.1p-vs2010"

    condition:
        5 of them
}