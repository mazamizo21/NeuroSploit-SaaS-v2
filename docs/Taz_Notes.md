# Run integration test
docker exec -e TEST_TARGET=http://host.docker.internal:8888 \
  neurosploit-kali python3 /opt/open-interpreter/test_full_integration.py

# View LLM logs
docker exec neurosploit-kali cat /pentest/logs/llm_interactions.jsonl

# View execution logs
docker exec neurosploit-kali cat /pentest/logs/executions.jsonl

# Run E2E tests
./scripts/test_e2e.sh