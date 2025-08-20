rule logins {
    meta:
        description = "Detects login attempts"
        author = "Your Name"
        date = "2023-10-01"
        version = "1.0"

    strings:
        $login_attempt1 = "login failed" nocase
        $login_attempt2 = "invalid username or password" nocase
        $login_attempt3 = "access denied" nocase
        $login_attempt4 = "authentication required" nocase
        $login_attempt5 = "user not found" nocase
        $login_attempt6 = "password expired" nocase

    condition:
        any of ($login_attempt*)
}