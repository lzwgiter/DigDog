rule Dyre : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Dyre"
		sample = "md5: 7ee298202f77027fe276439d390a345b"

	strings:
		$string_1 = "success resolved b32-address"
		$string_2 = "send browsnapshot failed"
		$string_3 = "send system info failed"
		$method = "MapViewOfFile"

	condition:
		all of them
}
