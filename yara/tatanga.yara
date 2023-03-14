rule Tatanga : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Tatanga"
		sample = "md5: 18ce528749eaa549ff393cdcf7cff573"

	strings:
		$string_1 = "hounthickChGetTTS"
		$string_2 = "hFreehHeapTS"

	condition:
		all of them
}

rule Tatanga2 : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Tatanga"
		sample = "md5: 18ce528749eaa549ff393cdcf7cff573"

	strings:
		$string_1 = "mail.yaklasim.com:8080/ponyb/gate.php"

	condition:
		all of them
}
