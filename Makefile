.PHONY: build lint test demo

CORE_SRC := packages/guardrails-core/src/guardrails_core
VENDOR := packages/guardrails-plugin/vendor/guardrails_core

# Vendoring: copy core into the plugin so the plugin folder works on its own, with stock python3.
build:
	rm -rf $(VENDOR)
	mkdir -p $(VENDOR)
	cp $(CORE_SRC)/*.py $(VENDOR)/
	find packages -name __pycache__ -prune -exec rm -rf {} +

lint:
	uv run ruff check .

test: build
	uv run pytest -q

demo: build
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/guardrails-core/src:packages/guardrails-demo/src \
		python3 -m guardrails_demo
