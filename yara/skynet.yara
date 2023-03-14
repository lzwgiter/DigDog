rule skynet : injector
{
	strings:
		$string_1 = "LdrGetDllHandle"
		$string_2 = "0x75026848"
		$string_3 = "if exist \"%s\" goto d"

	condition:
		all of them
}

rule skynet2 : injector
{
	strings:
		$string_1 = "sha256_cryptopp.c"
		$string_2 = "tkpktox73usm5vq.onion:80/reverseproxy.txt"
		$string_3 = "User-Agent: pony"

	condition:
		all of them
}

rule skynet3 : injector
{
	strings:
		$string_1 = "reverseproxy.txt"
		$string_2 = "cygming-crtbegin.c"
		$string_3 = "127.0.0.1:9050"

	condition:
		all of them
}