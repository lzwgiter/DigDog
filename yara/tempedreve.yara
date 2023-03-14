rule tempedreve : injector
{
	strings:	
		$string1 = "client: %08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x"
		$string2 = "minicheck: %s"
        $string3 = "SCREENSHOT"
	condition:
		all of them
}
