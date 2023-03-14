rule Sality : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Sality"
		sample = "md5: 5e4f1f1aa595c354413090e172e8fd91"

	strings:
		$fileMapping_1 = "purity_control_90833"
		$fileMapping_2 = "hh8geqpHJTkdns0"
		// https://blog.fortinet.com/post/salted-algorithm-part-1

	condition:
		all of them
}
