rule Sinowal : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Sinowal"
		sample = "md5: e2de3f56b9f0278d0515a0ce91a816b2"

	strings:
		$string_1 = "\"%s\\Google\\Chrome\" /T /grant *S-1-1-0:F"
		$string_2 = "Thank you for choosing AVG product!"

	condition:
		1 of them
}
