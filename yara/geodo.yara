rule Geodo : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Geodo"
		sample = "md5: 1bb9db20d591bbdf599060f2b5a9e193"

	strings:
		$method_1 = "NtMapViewOfSection"
		$method_2 = "NtQueueApcThread"
		$url = "http://%s/%x/%x/"
		$agent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"

	condition:
		all of them
}

rule Geodo2 : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Geodo"
		sample = "md5: 1bb9db20d591bbdf599060f2b5a9e193"

	strings:
		$s1 = "Host: 192.154.110.228:8080"
        $s2 = "jsproxy.dll"
        $s3 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $s4 = "AccountControlSettings.exe"
        $s5 = "Mozilla/5.0"

	condition:
		all of them
}