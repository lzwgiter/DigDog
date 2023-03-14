rule propagation{
    meta:
        author = "QYDD"
        version = "0.1"
        shortcoming = ""
        description = "Detects whether the trojan has propagation related activities."
    
    strings:
        $wireless_communication_protocol1 = "Wi-Fi"
        $wireless_communication_protocol2 = "802.11"
        $wireless_communication_protocol3 = "WPA"
        $wireless_communication_protocol4 = "WPA2"
        $wireless_communication_protocol5 = "WPA3"
        $wireless_communication_protocol6 = "IrDA"
        $wireless_communication_protocol7 = "ZigBee"
        $wireless_communication_protocol8 = "WiMedia"
        $wireless_communication_protocol9 = "CDMA"
        $wireless_communication_protocol10 = "Bluetooth"
        $wireless_communication_protocol11 = "Z-wave"
        $wireless_communication_protocol12 = "UWB"
        $wireless_communication_protocol13 = "WiGig"
        $wireless_communication_protocol14 = "WUSB"
        $wireless_communication_protocol15 = "WiHD"
        $wireless_communication_protocol16 = "WHDI"
        $wireless_communication_protocol17 = "NFC"
        $wireless_communication_protocol18 = "RFID"
        $wireless_communication_protocol19 = "GPS"

        $enumeration_port_API1 = "WlanEnumInterfaces"
        $enumeration_port_API2 = "WlanGetInterfaceCapability"
        $enumeration_port_API3 = "WlanQueryInterface"
        $enumeration_port_API4 = "WlanSetInterface"
        $enumeration_port_API5 = "WlanScan"
        $enumeration_port_API6 = "WlanGetAvailableNetworkList"
        $enumeration_port_API7 = "WlanGetProfile"
        $enumeration_port_API8 = "WlanSetProfile"
        $enumeration_port_API9 = "WlanDeleteProfile"
        $enumeration_port_API10 = "WlanConnect"
        $enumeration_port_API11 = "WlanDisconnect"
    condition:
        any of ($wireless_communication_protocol*) and 2 of ($enumeration_port_API*)
}