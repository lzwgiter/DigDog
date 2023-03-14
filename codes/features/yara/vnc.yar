rule vnc{
    meta:
        author = "QYDD"
        version = "0.1"
        shortcoming = ""
        description = "Detects malwares using vnc-related characters."
    
    strings:
        $vnc_protocol1 = "RMI"
        $vnc_protocol2 = "RPC"
        $vnc_protocol3 = "SOAP"
        $vnc_protocol4 = "CORBA"
        $vnc_protocol5 = "JMS"
        $vnc_protocol6 = "JBoss-Remoting"
        $vnc_protocol7 = "Spring-Remoting"
        $vnc_protocol8 = "Hessian"
        $vnc_protocol9 = "Burlap"
        $vnc_protocol10 = "XFire"
        $vnc_protocol11 = "Axis"
        $vnc_protocol12 = "ActiveMQ"
        $vnc_protocol13 = "Mina"
        $vnc_protocol14 = "SSH"
        $vnc_protocol15 = "EJB"
        $vnc_protocol16 = "Telnet"
        $vnc_protocol17 = "Rlogin"
        $vnc_protocol18 = "RFB"
        $vnc_protocol19 = "RDP"
    condition:
        any of them
}