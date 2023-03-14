rule razorcrypt: crypter
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2015-03-23"
        description = "Razorcrypt is a cryptor that injects its payload during decryption"

    strings:
    $s_1 = "E:\\MsgBoxHelloWorld\\Release\\MsgBoxHelloWorld.pdb"
    $s_2 = "MessageBoxW"

    condition:
        all of them
}
