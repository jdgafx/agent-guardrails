.PHONY: build lint test demo isolation dashboard

CORE_SRC := packages/guardrails-core/src/guardrails_core
VENDOR := packages/guardrails-plugin/vendor/guardrails_core

# Vendoring: copy core into the plugin so the plugin folder works on its own, with stock python3.
build:
	rm -rf $(VENDOR)
	mkdir -p $(VENDOR)
	cp $(CORE_SRC)/*.py $(VENDOR)/
	find packages -name __pycache__ -prune -exec rm -rf {} +

# The sandbox settings block for opt-in isolation, generated from policy.json. Run it after the
# secret rules change and commit the file; a test fails while the committed file is stale.
isolation:
	mkdir -p packages/guardrails-plugin/isolation
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/guardrails-core/src python3 -m guardrails_core.isolation packages/guardrails-plugin/policy.json > packages/guardrails-plugin/isolation/settings.local.json

lint:
	uv run ruff check .

test: build
	uv run pytest -q

demo: build
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/guardrails-core/src:packages/guardrails-demo/src \
		python3 -m guardrails_demo

# The local read-only dashboard server. It imports core from its source folder, so it needs no build.
dashboard:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/guardrails-core/src:packages/guardrails-dashboard/src \
		python3 -m guardrails_dashboard
