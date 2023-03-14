rule confickerB : injector
{
	strings:
		$s1 = "spamhaus"
		$s2 = "computerassociates"
		$s3 = "NetpwPathCanonicalize"
		$s4 = "useautoplay=1"
		$s5 = "aol.com"
		$s6 = "macintosh"
		$s7 = "SMBs"
		$s8 = "upnp:rootdevice"
		$s9 = "eventSubURL"
	condition:
		6 of them
}

