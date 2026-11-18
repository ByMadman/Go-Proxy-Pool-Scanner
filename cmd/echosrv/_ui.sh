set -e
cd /www/wwwroot/proxy
cat > /tmp/verify_ui.json <<'JSON'
{"dialTimeout":4000,"totalTimeout":8000,"maxBodySize":65536,"userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36","echoServers":[{"url":"http://192.187.105.21:8849/get","kind":"headers","note":"自建回显（同端口支持 HTTP+HTTPS，自动判定匿名等级）"},{"url":"http://api.ipify.org?format=json","kind":"ip","note":"仅回显出口 IP（连通兜底）"},{"url":"https://api.ipify.org?format=json","kind":"ip","note":"HTTPS 出口 IP（连通兜底）"},{"url":"http://ip-api.com/json/","kind":"ip","note":"出口 IP 与归属地"},{"url":"http://myip.ipip.net","kind":"ip","note":"文本出口 IP"},{"url":"https://www.taobao.com/help/getip.php","kind":"ip","note":"文本出口 IP"},{"url":"http://www.baidu.com","kind":"connect","note":"连通性兜底"},{"url":"https://www.baidu.com","kind":"connect","note":"HTTPS 连通性兜底"}],"httpsTargets":["https://api.ipify.org?format=json","https://www.baidu.com","https://www.qq.com"],"publicIp":"192.187.105.21","maxHeaderTries":3,"maxIpTries":2,"maxHttpsTries":2,"concurrencyHint":0}
JSON
sqlite3 proxy.db "UPDATE settings SET value=(SELECT readfile('/tmp/verify_ui.json')) WHERE key='verify';"
echo "== headers now =="
sqlite3 proxy.db "SELECT value FROM settings WHERE key='verify';" | grep -o '"url":"[^"]*","kind":"headers"'
systemctl restart proxyscanner
sleep 2
systemctl is-active proxyscanner