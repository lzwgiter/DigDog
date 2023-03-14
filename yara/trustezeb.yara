rule Trustezeb : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-02-04"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Trustezeb"
		sample = "md5: ca84aaa02f68b4edd938a1840e6a3a91"

	strings:
		$vm_1 = "VmWare"
		$vm_2 = "VirtualBox"
		$vm_3 = "VirtualPC"

		$software_1 = "panda_url_filtering.exe"
		$software_2 = "bullguardbhvscanner.exe"

		$string_1 = "TASKKILL /F /FI \"USERNAME eq %s\" /FI \"PID ne %u\" /IM svchost.exe"
		$string_2 = "dlllist=%s&proclist=%s"
		$string_3 = "id=%s&ver=%s&cvr=%u&threadid=%u&lang=0x%04X&os=%s&%s"
		$string_4 = "EXECDLLFM:"

	condition:
		all of them
}
