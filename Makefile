packages = panther_classic_converter

.PHONY: lint
lint:
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r $(packages)

.PHONY: test
test:
	python -m unittest discover 

.PHONY: install
install:
	pipenv install --dev

.PHONY: sync
sync:
	pipenv sync --dev

package-clean:
	rm -rf dist
	rm -f MANIFEST

package: package-clean install test lint
	pipenv run python3 setup.py sdist

publish: package
	twine upload dist/*
