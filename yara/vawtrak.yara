rule Vawtrak : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Vawtrak"
		sample = "md5: 7b05cc5f48c389a53a42ca1a8e4b2957"

	strings:
		$network_1 = "[BC] Fail Connect"
		$network_2 = "[BC] Fail send auth"
		$misc = "<HTTPMail_Password2"

	condition:
		all of them
}
