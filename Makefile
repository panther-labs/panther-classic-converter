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

install: venv
	pipenv lock -r > requirements.txt

package-clean:
	rm -rf dist
	rm -f MANIFEST

package: package-clean install test lint
	pipenv run python3 setup.py sdist

publish: install package
	twine upload dist/*