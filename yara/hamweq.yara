rule hamweq : injector
{
	strings:
		$string_1 = "hostsv.exe"
		$string_2 = "hifaggot"
		$string_3 = "GURLv2"
		$string_4 = "Infected usb drive"

	condition:
		// all strings are in explorer.exe, but in different memory segments
		// so the rule doesn't match with "all of them"
		any of them
}
