rule Kovter : Clickfraud
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Kovter is involved in click-fraud. See http://www.symantec.com/connect/blogs/kovter-malware-learns-poweliks-persistent-fileless-registry-update"
        version = "2016-01"
        names = "Kovter"
        sample = "md5: 7c640fba7d917ad0c499adacd4b2e4b3"

    strings:
        $useragent1 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $useragent2 = "MSIE 10.0"
        $useragent3 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)"
        $useragent4 = "MSIE 9.0"
        $useragent5 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
        $useragent6 = "MSIE 8.0"
        $useragent7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; InfoPath.3)"
        $useragent8 = "MSIE 7.0"
        $useragent9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.30729)"
        $useragent10 = "MSIE 6.0"
        $clickfraud1 = "try {var els=document.getElementsByTagName('object'); for(var i=0;i<els.length;i++){ els[i].play();}} catch(e){}"
        $clickfraud2 = "try {var els=document.getElementsByTagName('embed'); for(var i=0;i<els.length;i++){ els[i].playVideo();}} catch(e){}"
        $clickfraud3 = "try {var els=document.getElementsByTagName('object'); for(var i=0;i<els.length;i++){ els[i].START();}} catch(e){}"
        $clickfraud4 = "try {jwplayer().play()} catch(e){}"
        $clickfraud5 = "Referer:"
        $clickfraud6 = "<a href="
        $clickfraud7 = ">click<"
        $random1 = "DigitalProductId"
        $random2 = "InstallDate"
        $random3 = ".exe"
        $random4 = "UrlMkSetSessionOption"
        $random5 = "PADDINGXX"
        $random6 = "SOFTWARE\\Borland\\Delphi\\RTL"


    condition:
        3 of ($useragent*) and 4 of ($random*) and 2 of ($clickfraud*)
}

rule Kovter_packer : Clickfraud
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Kovter is involved in click-fraud. See http://www.symantec.com/connect/blogs/kovter-malware-learns-poweliks-persistent-fileless-registry-update"
        version = "2016-01"
        names = "Kovter"
        sample = "md5: 7c640fba7d917ad0c499adacd4b2e4b3"

    strings:
        $s1 = "Portions Copyright"
        $s2 = "GetCurrentThreadId"
        $s3 = "FindResourceW"
        $s4 = "tMjJGASXl3X6xbNSarE"


    condition:
        all of them
}