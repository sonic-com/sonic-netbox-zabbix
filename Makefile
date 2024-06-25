requirements.txt: pyproject.toml poetry.lock

	poetry export --no-interaction --format=requirements.txt --without-hashes --all-extras --with-credentials --output=requirements.txt
	echo "--extra-index-url https://repo.sonic.net/sonic_python_packages" >> requirements.txt
	echo sonic-logger >> requirements.txt

poetry.lock: pyproject.toml
	poetry lock
