# Network access example (blocked by default)
import requests

response = requests.get("https://example.com")
print(response.text)
