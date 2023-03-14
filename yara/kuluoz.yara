rule Kuluoz : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Kuluoz / Asprox"
		sample = "md5: da59d53d5feb526c9c413bee6f1be06c"

	strings:
		$mail_1 = "RECIPIENT: Mark Smith"
		$mail_2 = "LOCATION OF YOUR PARCEL: Los Angeles"
		$mail_3 = "STATUS OF YOUR ITEM: not delivered"
		$mail_4 = "SERVICE: Standard Shipping"

	condition:
		all of them
}

rule Kuluoz_packer : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Kuluoz / Asprox"
		sample = "md5: da59d53d5feb526c9c413bee6f1be06c"

	strings:
		$1 = "66.84.10.68:8080"
		$2 = "50.57.135.154:8080"
		$3 = "46.4.178.174:8080"
		$4 = "User-Agent: Mozilla"

	condition:
		all of them
}
