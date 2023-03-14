rule zeus_7_8 : injector
{
	strings:
		$string_1 = "vKDDKEHq"
		$string_2 = "fkihdcwkbb"
		$string_3 = "tsfpkejc"

	condition:
		all of them
}
