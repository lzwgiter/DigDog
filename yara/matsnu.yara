rule matsnu : injector
{
	strings:
		$string1 = "cmd=key&ver=%s&data=%u:%u:%s"
		$string2 = "stat=%u&ver=%s"
		$string3 = "%s?id=%s&%s"
		$string4 = "QQasd123zxc"
	condition:
		all of them
}

rule matsnu2 : injector
{
	strings:
		$string1 = "http://robertos-group.com/images/a.php"
		$string2 = "horad-fo.com"
	condition:
		all of them
}



