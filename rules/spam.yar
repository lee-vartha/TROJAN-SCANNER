rule spam {
    meta:
        description = "Detects spam activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"
    
    strings:
        $spam1 = "Congratulations! You've won a prize!" nocase
        $spam2 = "Click here to claim your reward" nocase
        $spam3 = "Limited time offer" nocase
        $spam4 = "Act now!" nocase
        $spam5 = "Unsubscribe" nocase
        $spam6 = "casino" nocase
        $spam7 = "free gift card" nocase
        $spam8 = "urgent action required" nocase
        $spam9 = "from:" nocase fullword
        $spam10 = "subject:" nocase fullword
        $spam11 = "Dear user," nocase fullword
        $spam12 = "Dear valued customer," nocase fullword

    condition:
        3 of ($spam*)
}