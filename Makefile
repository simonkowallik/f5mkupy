.PHONY: clean clean-test clean-pyc clean-build docs help

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg-info' -exec rm -fr {} +
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -f coverage.xml
	rm -f coverage.lcov
	rm -fr htmlcov/
	rm -fr .pytest_cache
	find . -name '.mypy_cache' -exec rm -fr {} +

lint:
	pylint f5mkupy/*.py
	pylint tests/*.py

black:
	black f5mkupy/*.py
	black tests/*.py

isort:
	isort f5mkupy/*.py
	isort tests/*.py

code-format: isort black # black has the last word

test:
	pytest --cov=f5mkupy tests/
	coverage html
	coverage lcov
	coverage xml
	coverage report -m

tests: test

publish-test-pypi: dist
#	poetry config repositories.test-pypi https://test.pypi.org/legacy/
#	poetry config pypi-token.test-pypi $(TOKEN)
	poetry publish -r test-pypi

publish-pypi: dist
#	poetry config repositories.pypi https://test.pypi.org/legacy/
#	poetry config pypi-token.pypi $(TOKEN)
	poetry publish -r pypi

dist: clean ## builds source and wheel package
	poetry build
	ls -l dist
	tar tzf dist/*.tar.gz