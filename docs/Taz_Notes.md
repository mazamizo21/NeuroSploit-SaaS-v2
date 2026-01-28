# Run integration test
docker exec -e TEST_TARGET=http://host.docker.internal:8888 \
  tazosploit-kali python3 /opt/open-interpreter/test_full_integration.py

# View LLM logs
docker exec tazosploit-kali cat /pentest/logs/llm_interactions.jsonl

# View execution logs
docker exec tazosploit-kali cat /pentest/logs/executions.jsonl

# Run E2E tests
./scripts/test_e2e.sh


cat logs/agent_report_20260111_211806.json | jq '.' 2>/dev/null

to access file was created by the pentest :

mkdir -p extracted
./run-unlimited-test.sh
# After completion:
ls extracted/
unzip extracted/*.zip
cat extracted/flags.txt