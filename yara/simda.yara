rule simda : injector
{
	strings:
		$string1 = "secret.key"
		$string2 = "HookExplorer.exe"
		$string3 = "wireshark.exe"
        $string4 = "botid=%s&ver=1.0.2&up=%u&os=%03u&rights=%s&ltime=%s%d&token=%"
	condition:
		all of them
}

