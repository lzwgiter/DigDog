rule tinybanker : injector
{
	strings:	
		$string1 = "-----BEGIN PUBLIC KEY-----"
		$string2 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA69BWWO2R/EGkAiRi1sxa"
        $string3 = "%BOTUID%VW"
	condition:
		all of them
}
