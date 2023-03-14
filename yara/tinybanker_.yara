rule Tinybanker_2016 : Banker {

strings:
	$s1 = "RtlCreateUserThread"
	$s2 = "Packages\\windows_ie_ac_001\\AC\\"
	$s3 = "grb.dat"

condition:
	all of them
}

