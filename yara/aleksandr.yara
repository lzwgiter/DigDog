rule aleksandr : dropper
{
  meta:
    author = "thomas.barabosch@fkie.fraunhofer.de"
    description = "(see https://blog.fortinet.com/2016/06/21/the-curious-case-of-an-unknown-trojan-targeting-german-speaking-users)"

  strings:
    $s1 = "IsWow64Process"
    $s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET4.0C; .NET4.0E)"
    $s3 = "LdrLoadDll"
    $s4 = "http://remembermetoday4.asia/00/c.bin;"
    $s5 = "http://remembermetoday4.asia/00/b.bin;"

  condition:
    4 of them
}