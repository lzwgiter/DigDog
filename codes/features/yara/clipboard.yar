rule clipboard{
    meta:
        author = "QYDD"
        version = "0.1"
        shortcoming = "Whether the clipboard_API_NET strings will cause erroneus judgement."
        description = "Detects trojan activites using clipboard related APIs"
    strings:
        $clipboard_API_Server1 = "AddClipboardFormatListener"
        $clipboard_API_Server2 = "ChangeClipboardChain"
        $clipboard_API_Server3 = "CloseClipboard"
        $clipboard_API_Server4 = "CountClipboardFormats"
        $clipboard_API_Server5 = "EmptyClipboard"
        $clipboard_API_Server6 = "EnumClipboardFormats"
        $clipboard_API_Server7 = "GetClipboardData"
        $clipboard_API_Server8 = "GetClipboardFormatName"
        $clipboard_API_Server9 = "GetClipboardOwner"
        $clipboard_API_Server10 = "GetClipboardSequenceNumber"
        $clipboard_API_Server11 = "GetClipboardViewer"
        $clipboard_API_Server12 = "GetOpenClipboardWindow"
        $clipboard_API_Server13 = "GetPriorityClipboardFormat"
        $clipboard_API_Server14 = "GetUpdatedClipboardFormats"
        $clipboard_API_Server15 = "IsClipboardFormatAvailable"
        $clipboard_API_Server16 = "OpenClipboard"
        $clipboard_API_Server17 = "RegisterClipboardFormat"
        $clipboard_API_Server18 = "RemoveClipboardFormatListener"
        $clipboard_API_Server19 = "SetClipboardData"
        $clipboard_API_Server20 = "SetClipboardViewer"

        $clipboard_API_NET1 = "Clear"	
        $clipboard_API_NET2 = "ContainsAudio"	
        $clipboard_API_NET3 = "ContainsData"
        $clipboard_API_NET4 = "ContainsFileDropList"	
        $clipboard_API_NET5 = "ContainsImage"
        $clipboard_API_NET6 = "ContainsText"
        $clipboard_API_NET7 = "Flush"	
        $clipboard_API_NET8 = "GetAudioStream"	
        $clipboard_API_NET9 = "GetData"	
        $clipboard_API_NET10 = "GetDataObject"
        $clipboard_API_NET11 = "GetFileDropList"	
        $clipboard_API_NET12 = "GetImage"	
        $clipboard_API_NET13 = "GetText"
        $clipboard_API_NET14 = "IsCurrent"	
        $clipboard_API_NET15 = "SetAudio"
        $clipboard_API_NET16 = "SetData"
        $clipboard_API_NET17 = "SetDataObject"	
        $clipboard_API_NET18 = "SetFileDropList"	
        $clipboard_API_NET19 = "SetImage"		
        $clipboard_API_NET20 = "SetText"
    condition:
        any of ($clipboard_API_Server*) or any of ($clipboard_API_NET*)
 
}