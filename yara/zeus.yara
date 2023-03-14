rule zeus : injector
{
	strings:
		$string1 = "*<input *value=\""
		$string2 = "*<option  selected"
		$string3 = "*<select"
	condition:
		all of them
}

rule zeus2 : injector
{
	strings:
		$string1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; SV1)"
		$string2 = "if exist"
		$string3 = "FCIFlushCabinet"
	condition:
		all of them
}