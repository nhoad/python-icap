PYTHON:=/usr/bin/python3
PYTEST:=`which py.test`
COVERAGE_RUN:=`which coverage3` run --append

run-tests: clean-coverage unit-tests service-tests
	coverage html --include="icap/*"
	coverage report --include="icap/*"

clean-coverage:
	rm -rf .coverage htmlcov

unit-tests-fastfail:
	$(PYTHON) $(COVERAGE_RUN) $(PYTEST) tests/test_*.py -x

unit-tests:
	$(PYTHON) $(COVERAGE_RUN) $(PYTEST) tests/test_*.py

service-tests:
	$(PYTHON) tests/servicetest*.py

doc:
	make -C docs html
