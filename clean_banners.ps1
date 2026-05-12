$file = "c:\Users\Admin\Desktop\FYP code\SDVN-Temporal-Attacks\routing.cc"
$enc  = [System.Text.Encoding]::UTF8
$content = [System.IO.File]::ReadAllText($file, $enc)

# Remove the banner from steps 3, 4, 5, 6, 7
$content = $content -replace '(?s)    std::stringstream ss;\r?\n    ss << "========================================\\n"\r?\n       << "  PAIR: ATTACKER=" << [a-zA-Z0-9_]+ << "  VICTIM=" << [a-zA-Z0-9_]+ << "\\n"\r?\n       << "========================================\\n"\r?\n       << "\[t=', '    std::stringstream ss;' + "`n" + '    ss << "[t='

# Remove inline banner from Step 2
$content = $content -replace '(?s)\[t=" << now << "\]  STEP ②  LEGITIMATE HEARTBEATS TO CONTROLLER\\n"\r?\n       << "  \[Pair: ATTACKER=" << v2Label << "  VICTIM=" << v1Label << "\]\\n"\r?\n', '[t=" << now << "]  STEP ②  LEGITIMATE HEARTBEATS TO CONTROLLER\n"\n'

# Replace "t=" with "beacon_sending_time=" in the logs
$content = $content -replace 't=" << stored_time', 'beacon_sending_time=" << stored_time'
$content = $content -replace 't=" << t', 'beacon_sending_time=" << t'
$content = $content -replace 'timestamp t=', 'timestamp beacon_sending_time='
$content = $content -replace '\(Sender=Victim, t=5\)', '(Sender=Victim, beacon_sending_time=5)'
$content = $content -replace '\(Sender=Attacker, t=5\)', '(Sender=Attacker, beacon_sending_time=5)'

[System.IO.File]::WriteAllText($file, $content, $enc)
Write-Host "Formatting cleaned up!"
