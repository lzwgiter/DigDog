rule Afcore : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Afcore / Coreflood"
		sample = "md5: 4d27b641939f86bd8cc7fdcd1d2815e5"

	strings:
		$string_1 = "AFCORE_BASE"
		$string_2 = "Internet Explorer_Server"
		$string_3 = "Assertion has failed in .\\src\\iexplore.cpp(%d)"
		$string_4 = "Removing AF from the system . . ."
		$string_5 = "Attempting to spawn octopus . . ." // UNLEASH THE KRAKEN

		$method = "MapViewOfFile"

	condition:
		all of them
}

rule Afcore2 : injector
{
	strings:
		$string_1 = "hi sweetie"
		$string_2 = "UNINSTALL"
		$string_3 = "WININIT.INI"
		$string_4 = "AFCORE"
		$string_5 = "AF.dll"

	condition:
		4 of them
}
