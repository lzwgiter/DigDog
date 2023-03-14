rule cryptolockerracketeer : cryptolocker
{
    strings:
		$a = "Tools_Android_Pacage"
		$b = "Cyber_com_.mdb" fullword nocase
		$c = "X:\\racketeer\\solutions\\new\\output\\Release\\bin\\rack-core.pdb" fullword nocase

     condition:
        ($a and $b) or $c
}

