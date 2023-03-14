rule atmos : banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://otx.alienvault.com/pulse/570f9027aef92133b75e1d4f/"
        sample = "md5: 3615d7e5619ad5fee340c5823cb051d6"

    strings:
         $s1 = "X-Content-Security-Policy"
         $s2 = "update.exe"
         $s3 = "config.bin"
         $s4 = "X-WebKit-CSP"
         $s5 = "PUT"
         $s6 = "http://www.google.com/webhp"
         $s7 = "_getFirefoxCookie"
         $s8 = "%BOTID%"
         $s9 = "%BOTNET%"

         $atmos1 = "atmos_hvnc.module"
         $atmos2 = "atmos_ffcookie.module"
         $atmos3 = "atmos_video.module"


    condition:
        (5 of ($s*)) and (2 of ($atmos*))
}