rule Bredolab : injector
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2016-06-23"
		version = "1.0"
		sample = "md5: "

	strings:
		$string_1 = "updatec"
		$string_2 = "download1"
		$string_3 = "&uptime=%d&rnd=%d"
		$string_4 = "Our_Agent"
		$string_5 = "?bid=%08x%08x"
		$string_6 = "dxdiag.exe"
		$string_7 = "&os=%d-%d-%d"

	condition:
		4 of them
}