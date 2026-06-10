#!/bin/bash

GATEWAY_URL="http://localhost:18080"
TRADITIONAL_KEY="admin-pass-558"
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJEaXNjb3JkX0Rldl9QYXJ0bmVyIiwiaWF0IjoxNzE3OTc0NDAwLCJleHAiOjIyMjE5NDU2MDB9.Vb8W_gshm6GqHw36YAnC8yT8-jGgO7Z0Vb-r6uUqW64"
echo "=================================================="
echo "🚀 Go-digiRunner 大規模自動化功能驗證測試開始"
echo "=================================================="

echo -e "\n🔎 [測試 1] 向下相容：傳統 API Key 資料庫查表測試"
curl -s -o /dev/null -w "▶️ 回應狀態碼: %{http_code}\n" -H "Authorization: Bearer $TRADITIONAL_KEY" "$GATEWAY_URL/service-a/get"

echo -e "\n🔎 [測試 2] 標準 JWT：原生記憶體密鑰高速解密測試"
curl -s -o /dev/null -w "▶️ 回應狀態碼: %{http_code}\n" -H "Authorization: Bearer $JWT_TOKEN" "$GATEWAY_URL/service-b/zen"

echo -e "\n🔎 [測試 3] 資安防禦：使用偽造/錯誤的認證憑證"
curl -s -o /dev/null -w "▶️ 回應狀態碼: %{http_code}\n" -H "Authorization: Bearer wrong-token-123" "$GATEWAY_URL/service-a/get"

echo -e "\n🔎 [測試 4] 負載平衡：連續呼叫 4 次，觀察後端輪詢 (Round-Robin) 切換"
# 注意：為了避開限流，我們每戳一次稍微 sleep 0.6 秒，確保權杖足夠
for i in {1..4}
do
    echo "  👉 第 $i 次呼叫 lb-test..."
    curl -s -H "Authorization: Bearer $TRADITIONAL_KEY" "$GATEWAY_URL/lb-test/zen" | grep -E "message|uuid" || echo "  (查看網關終端機確認轉發目標)"
    sleep 0.6
done

echo -e "\n🔎 [測試 5] 限流恢復：等待 2 秒讓權杖桶補滿，測試單發連線"
sleep 2
curl -s -o /dev/null -w "▶️ 回應狀態碼: %{http_code}\n" -H "Authorization: Bearer $TRADITIONAL_KEY" "$GATEWAY_URL/service-a/get"

echo "=================================================="
echo "🏁 測試腳本執行完畢，請到網關後台 /admin 觀察最新流量統計 (Hits)！"
echo "=================================================="