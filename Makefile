# Targets for local development
shell::   pipenv shell
install:: ci_install
sync::    ci_sync 
fmt::     ci_fmt
lint::    fmt ci_lint
test::    fmt ci_lint ci_test

# Targets for CI
ci_fmt::
	pipenv run black panther_classic_converter tests

ci_lint::
	pipenv run mypy panther_classic_converter tests --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r panther_classic_converter tests

ci_test::
	pipenv run python -m unittest discover 

ci_install:
	pipenv install --dev

ci_sync:
	pipenv sync --dev

# Other targets
publish:
	rm -rf dist
	rm -f MANIFEST
	pipenv run python3 setup.py sdist
	pipenv run twine upload ./dist/*