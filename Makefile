.PHONY: install bootstrap bootstrap-kev test lint up down

install:
	pip install -e ".[dev,compression]"

bootstrap:
	python -m pipeline.bootstrap

bootstrap-kev:
	python -m pipeline.bootstrap --kev-seed

test:
	pytest -v

lint:
	ruff check .

up:
	docker compose up -d --build

down:
	docker compose down
