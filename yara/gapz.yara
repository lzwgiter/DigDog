rule gapz : injector
{
	strings:
		$string_1 = "dropper.exe"
		$string_2 = "GAPZ"
		$code = { c7 45 cc da ee 6c 75 }

	condition:
		all of them
}
