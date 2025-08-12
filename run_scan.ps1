$ts = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Path ".\out" -Force | Out-Null
python .\main.py 192.168.1.0/24 --ports 22,80,443,445,3389,8080,8443,3000 --timeout 2.5 --html "out\lan_$ts.html"
python .\main.py 192.168.1.254 --ports 80,443 --timeout 3.0 --html "out\router_$ts.html"

powershell -ExecutionPolicy Bypass -File .\run_scan.ps1 > "out\lan_console_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" 2>&1

findstr /C:"Open ports" out\lan_console_YYYYMMDD_*.txt > out\summary_prev.txt
findstr /C:"Open ports" out\lan_console_YYYYMMDD_*.txt > out\summary_curr.txt
Format-Custom out\summary_prev.txt out\summary_curr.txt