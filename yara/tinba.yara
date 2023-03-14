rule tinba : injector
{
	strings:
        $string1 = "%BOTUID%"
        $string2 = "%BOTDATA_*%"
        $string3 = "POST /dataSafer3er/ HTTP/1.1"
      
	condition:
		all of them
}

