# Python client

`nexum_client.py` is a dependency-light client (`cryptography` + stdlib) that
signs a fresh proof for each request.

```bash
pip install cryptography
python nexum_client.py --gateway http://127.0.0.1:8080 \
  --grant root.jwt --key .nexum/keys/bot.key.json \
  --action example.read --resource app://x
```

`NexumClient.post(path, payload)` sends any JSON body (e.g. an MCP or A2A
JSON-RPC message) through the gateway with fresh credentials.
