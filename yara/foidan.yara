rule Foidan : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Foidan"
		sample = "md5: 991327984cc14474ad4e863a2543bad9"

	strings:
		$string_1 = "PADDINGPADDINGXX"
		$string_2 = "SAMEORIGIN"
		$method = "WriteProcessMemory"

	condition:
		all of them
}
