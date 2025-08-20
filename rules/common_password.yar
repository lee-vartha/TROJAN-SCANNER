// created to catch malware which does brute force attacks on accounts with logins
rule common_passwords {
    meta:
        description = "Detects common passwords"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"

    strings:
        $password1 = "123456"
        $password2 = "password"
        $password3 = "123456789"
        $password4 = "abc"
        $password5 = "qwerty"
        $password6 = "letmein"
        $password7 = "welcome"
        $password8 = "admin"
        $password9 = "iloveyou"
        $password10 = "pass"
    // can make a LOT more.
    condition:
        any of ($password*)        
}