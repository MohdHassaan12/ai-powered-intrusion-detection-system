rule WebExploit_CMD_Execute {
    meta:
        description = "Detects attempts to execute shell commands via web payloads"
        severity = "High"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/bin/sh" nocase
        $cmd3 = "/bin/bash" nocase
        $cmd4 = "powershell" nocase
    condition:
        any of them
}

rule SQL_Injection_Pattern {
    meta:
        description = "Common SQL injection signatures"
        severity = "Critical"
    strings:
        $s1 = "SELECT" nocase
        $s2 = "UNION ALL SELECT" nocase
        $s3 = "DROP TABLE" nocase
        $s4 = "' OR '1'='1" nocase
    condition:
        any of them
}

rule Shellcode_Pattern {
    meta:
        description = "Common NOP sled and shellcode distribution signatures"
        severity = "Critical"
    strings:
        $nop = "\x90\x90\x90\x90\x90\x90\x90\x90"
    condition:
        $nop
}

rule Phishing_Redirect {
    meta:
        description = "Suspicious URL redirection patterns"
        severity = "Medium"
    strings:
        $r1 = "window.location=" nocase
        $r2 = "http-equiv=\"refresh\"" nocase
    condition:
        any of them
}
