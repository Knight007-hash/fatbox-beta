/*
  Starter rules so the pipeline has something to fire on.
  Add real sets alongside this file (e.g. YARA-Forge core/extended, signature-base, ReversingLabs).
*/
rule FB_UPX_Packed
{
    meta:
        description = "UPX section names and stub marker"
        author = "FatBox"
    strings:
        $s0 = "UPX0" ascii
        $s1 = "UPX1" ascii
        $s2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule FB_Ransom_Note_Language
{
    meta:
        description = "Common ransom note phrasing"
        author = "FatBox"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decryption key" ascii wide nocase
        $c = ".onion" ascii wide nocase
        $d = "bitcoin" ascii wide nocase
    condition:
        2 of them
}

rule FB_Shadow_Copy_Wipe
{
    meta:
        description = "Shadow copy / recovery destruction commands (T1490)"
        author = "FatBox"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "wmic shadowcopy delete" ascii wide nocase
        $c = "recoveryenabled no" ascii wide nocase
        $d = "wbadmin delete catalog" ascii wide nocase
    condition:
        any of them
}

rule FB_Telegram_Discord_Exfil
{
    meta:
        description = "Chat-app API used as C2/exfil channel"
        author = "FatBox"
    strings:
        $a = "api.telegram.org/bot" ascii wide nocase
        $b = "discord.com/api/webhooks" ascii wide nocase
        $c = "discordapp.com/api/webhooks" ascii wide nocase
    condition:
        any of them
}
