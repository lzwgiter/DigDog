rule enfal : injector
{
	strings:
		$string_1 = "SS@SSPVSS"
		$string_2 = "VC20XC00U"

	condition:
		all of them
}
