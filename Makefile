packages = panther_classic_converter

.PHONY: venv
venv:
	pipenv install --dev

.PHONY: lint
lint:
	mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	bandit -r $(packages)

.PHONY: test
test:
	python -m unittest discover 

