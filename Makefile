requirements.txt: pyproject.toml uv.lock
	uv export --no-hashes --no-dev --no-emit-project --output-file=requirements.txt

uv.lock: pyproject.toml
	uv lock
