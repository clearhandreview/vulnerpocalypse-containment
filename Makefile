.PHONY: test syntax

test:
	python3 -m unittest discover -s tests -v

syntax:
	python3 -m py_compile cve98432.py
