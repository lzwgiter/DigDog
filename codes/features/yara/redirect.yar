rule redirect{
    meta:
        author = "QYDD"
        version = "0.1"
        shortcoimg = "More suspicious_urls are needed and this yara match rules would return True if the whole program contains JavaScript code segment.Unable to specifically test redirection. More analysis needed!"
        description = "Detects the trojans using redirection in JavaScript"
    strings:
        $suspicious_url1 = /http:\/\/gaup.*of.com/
        $suspicious_url2 = /http:\/\/gaup.*lone.braiinpower.com/
        $suspicious_url3 = /http:\/\/gaup.*e.hamefeats.com/
        $suspicious_url4 = /http:\/\/gaup.*w.obamafdacoverup.com/
        $suspicious_url5 = /http:\/\/gaup.*t.alignpaly.com/
        $suspicious_url6 = /http:\/\/gaup.*p.boardguff.com/
        $suspicious_url7 = /http:\/\/gaup.*e.scamlati.com/
        $suspicious_url8 = /https:\/\/*.*.com\/*/


        // Some banks in China
        $bank_related1 = "https://www.boc.cn"
        $bank_related2 = "https://www.icbc.com.cn"


        $js_charset_regex1 = /<script>*<\/script>/
        $js_charset_regex2 = /function*\(\)/
        $js_charset_regex3 = /<script type="*" src="*">*<\/script>/
        $js_charset_regex4 = /<*>/
        $js_charset_regex5 = /document.getElementbyId\(*\).innerHTML/

        $js_charset1 = "alert"
        $js_charset2 = "console.log"
        $js_charset3 = "document.write"
        $js_charset4 = "var"
        $js_charset5 = "document.getElementbyId" nocase
        $js_charset6 = "==="
        $js_charset7 = "!=="
        $js_charset8 = "NaN"
        
        // This part contains the concrete functions related to js redirection
        $js_charset14 = "window.location.href"
        $js_charset15 = "window.open"
        $js_charset16 = "window.history.back"
        $js_charset17 = "window.history.go"
        $js_charset18 = "window.navigate"
        $js_charset19 = "response.redirect"
        $js_charset20 = "document.writeIn"

        
    condition:
        (any of ($suspicious_url*) or any of ($bank_related*)) and  ( 3 of ($js_charset_regex*) or any of ($js_charset*))
}