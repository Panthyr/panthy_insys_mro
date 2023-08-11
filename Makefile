install:
	python -m pip install --upgrade pip
	python -m pip install -e .

prep:
	pre-commit run --all-files