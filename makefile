build: keys

keys: keys.nim
	nim c -o:$@ $@.nim

check:
	nimble check
	find . -name '*.sh' -exec shellcheck {} \;
	find . -name '*.md' \
		-exec aspell --dont-backup --personal ./.dict.pws check {} \; \
		-exec markdownlint --stdin \;

format:
	find . -name '*.sh' -exec shfmt -w {} \;

clean:
	git clean -fX

pre-commit: format check
