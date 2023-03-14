rule shylock : injector
{
	strings:
		$string_1 = "AVFF_Hook"
		$string_2 = "AVIE_Hook"
		$string_3 = "AVPE_Hook"
		$string_4 = "SeDebugPrivilege"

	condition:
		all of them
}
