.PHONY: skills-check skills-catalog skills-all

skills-check:
	./scripts/check_skills.sh

skills-catalog:
	python3 skills/scripts/rebuild_catalog.py

skills-all: skills-catalog skills-check
