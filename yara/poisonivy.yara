rule poisonivy1: injector {
    strings:
        $s1 = {55 8b ec 81 c4 30 fa ff ff 8b 75 08 8d 86 fb 03}
    condition:
        $s1
}

rule poisonivy2: injector {
    strings:
        $s1 = { 43 cc 57 e4 73 04 97 2c c3 5c f7 94 33 d4 77 1c }
    condition:
        $s1
}


