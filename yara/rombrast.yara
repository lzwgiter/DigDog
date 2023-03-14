rule rombrast : injector
{
	strings:
		$string1 = "open=%ws_a.exe"
        $string2 = "?act=spreading&ver=%s"
        $string3 = "data=USB<|>Infected Drive %c:\\<||>"
      
	condition:
		all of them
}

