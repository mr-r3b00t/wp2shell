/*
  webshells.yar — YARA rules for PHP webshells / backdoors.
  Scan a webroot:  yara -r webshells.yar /path/to/wp-content
  Tuned for the lab artifacts and common in-the-wild patterns; review before
  using in production (the generic rules can match legitimate code).
*/

rule php_request_to_exec_sink
{
    meta:
        description = "PHP passing request input directly into a command/eval sink"
        severity    = "high"
    strings:
        $php   = "<?php"
        $in1   = "$_GET"
        $in2   = "$_POST"
        $in3   = "$_REQUEST"
        $s1    = "shell_exec"
        $s2    = "system("
        $s3    = "passthru"
        $s4    = "proc_open"
        $s5    = "popen"
        $s6    = "eval("
        $s7    = "assert("
    condition:
        $php and any of ($in*) and any of ($s*) and filesize < 50KB
}

rule php_packed_eval
{
    meta:
        description = "Obfuscated/packed PHP: decoder feeding eval/assert"
        severity    = "high"
    strings:
        $php  = "<?php"
        $d1   = "base64_decode"
        $d2   = "gzinflate"
        $d3   = "gzuncompress"
        $d4   = "str_rot13"
        $e1   = "eval("
        $e2   = "assert("
        $e3   = "create_function"
    condition:
        $php and any of ($d*) and any of ($e*)
}

rule php_in_uploads_hint
{
    meta:
        description = "Tiny PHP file that looks like an uploads-dropped shell"
        severity    = "medium"
    strings:
        $php = "<?php"
        $a1  = "$_POST"
        $a2  = "$_GET"
        $a3  = "$_REQUEST"
        $b   = "eval"
        $c   = "base64_decode"
    condition:
        $php and filesize < 2KB and any of ($a*) and ($b or $c)
}

rule known_webshell_markers
{
    meta:
        description = "Signatures of well-known webshells / lab markers"
        severity    = "high"
    strings:
        $m1 = "__LABSHELL" nocase
        $m2 = "c99shell" nocase
        $m3 = "r57shell" nocase
        $m4 = "FilesMan" nocase
        $m5 = "b374k" nocase
        $m6 = "WSO " nocase
        $m7 = "weevely" nocase
    condition:
        any of them
}
