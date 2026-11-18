set -e
mkdir -p /www/wwwroot/echosrv
chmod +x /www/wwwroot/echosrv/echosrv
cp /tmp/echosrv.service /etc/systemd/system/echosrv.service
systemctl daemon-reload
systemctl enable echosrv
systemctl restart echosrv
sleep 2
echo "== status =="
systemctl is-active echosrv
echo "== firewall =="
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port=8849/tcp --permanent 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null || true
  echo "firewalld allowed 8849"
fi
if command -v ufw >/dev/null 2>&1; then
  ufw allow 8849/tcp 2>/dev/null || true
  echo "ufw allowed 8849"
fi
echo "== local test =="
curl -s http://127.0.0.1:8849/get
echo
echo "== remote test =="
curl -s http://192.187.105.21:8849/get