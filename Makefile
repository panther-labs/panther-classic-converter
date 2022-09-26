packages = panther_classic_converter

venv:
	pipenv install --dev

lint:
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r $(packages)

test:
	python -m unittest discover 

