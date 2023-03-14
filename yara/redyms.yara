rule Redyms : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Redyms"
		sample = "md5: 0044d66e4abf7c4af6b5d207065320f7"

	strings:
		$function_1 = "IsDebuggerPresent" // Nope :)
		$function_2 = "NtQueryInformationThread"
		$url_1 = "search.xxx"
		$url_2 = "/aol/search?"
		$url_3 = "search.icq.com"

	condition:
		all of them
}
