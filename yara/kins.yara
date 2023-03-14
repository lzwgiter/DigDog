rule Kins : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Kins"
		sample = "md5: 1883d9bc0f4f9ee8f19d171a90b4b70f"

	strings:
		$bot_1 = "DownloadRunExeUrl"
		$bot_2 = "InjectNormalRoutine"
		$bot_3 = "InjectApcRoutine"

	condition:
		any of them
}
