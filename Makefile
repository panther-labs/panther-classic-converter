packages = panther_classic_converter

venv:
	pipenv install --dev

lint:
	mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	bandit -r $(packages)

test:
	python -m unittest discover 

