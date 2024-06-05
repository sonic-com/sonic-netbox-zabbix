requirements.txt: pyproject.toml poetry.lock
	poetry export --format=requirements.txt --without-hashes > requirements.txt

poetry.lock: pyproject.toml
	poetry lock
