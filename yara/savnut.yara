rule Savnut : Banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Savnut is a banking Trojan"
        version = "2012"
        names = "Savnut"
        sample = "md5: d9699fffb7ff341f462749c04c1f29b3"

    strings:
        $programname1 = "smss.exe"
        $programname2 = "chrome.exe"
        $programname3 = "java.exe"
        $programname4 = "skype.exe"
        $programname5 = "outlook.exe"
        $programname6 = "msimn.exe"
        $programname7 = "WinMail.exe"
        $programname8 = "AVKTray.exe"
        $command1 = "BlockUrl"
        $command2 = "UpdateLoader"
        $command3 = "KeyStore"
        $command4 = "SearchDomain"
        $command5 = "ChkProxy"
        $command6 = "DllRegisterServer"
        $command7 = "ActivateProxy"
        $command8 = "PersonalTask"
        $command9 = "MainProcess"
        $command10 = "CheckBlocks"
        $network1 = "Content-Type: multipart/form-data; boundary="
        $network2 = "version2"
        $network3 = "&data_content="
        $network4 = "&action="
        $network5 = "&check=chck"
        $network6 = "&id=XXX_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        $network7 = "/index.php"
        $banking1 = "\\*roskildebank*"
        $banking2 = "\\*handelsbanken*"
        $banking3 = "\\*ringkjoebing-bank*"
        $banking4 = "\\*lollandsbank*"
        $banking5 = "\\*sparekassenthy*"
        $banking6 = "\\*bbvabancomerusa*"
        $banking7 = "\\*deltacommunitycu*"
        $banking8 = "portalbank"


    condition:
        5 of ($programname*) and 6 of ($command*) and 4 of ($network*) and 5 of ($banking*)
}
