rule Lethic : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Lethic"
		sample = "md5: 0460d89f0091d951184a8d77c6641340"

	strings:
		$url_1 = "zkijshg.com"
		$url_2 = "zlkishw.com"
		$url_3 = "zkkihsw.com"
		$url_4 = "zkijshw.com"

	condition:
		any of them
}
