# RedHunter WAF Quick Start

## 1. Running with Docker
```bash
docker-compose up -d
```

## 2. Testing Protection

```bash 
# Test SQLi (should be blocked)
curl "http://localhost:8080/search?q=1' OR 1=1--"

# Test XSS (should be blocked)
curl -X POST http://localhost:8080/comment \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(1)</script>"}'

# Check logs
docker-compose logs waf
```

## 3. Accessing Dashboard

- Kibana: http://localhost:5601

- API Docs: http://localhost:8000/docs




________________________



This complete implementation includes:
- Production-ready Docker setup
- Multi-layer detection (signatures + ML)
- Real-time blocking
- API for integration
- Comprehensive logging
- Test coverage

To use:
1. Clone the repository
2. Run `docker-compose up -d`
3. Configure your application to use the proxy (localhost:8080)


