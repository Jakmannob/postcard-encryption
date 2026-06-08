.PHONY: help keygen encrypt decrypt roundtrip clean serve test-web

PY    := uv run postcard.py
MSG   := message
KEY   := $(MSG).key.txt
PLAIN := $(MSG).txt
ENC   := $(MSG).enc.txt
NONCE := $(MSG).nonce.txt

help:
	@echo "Targets:"
	@echo "  make keygen          - generate a fresh AES-256 key into $(KEY)"
	@echo "  make encrypt         - encrypt $(PLAIN) -> $(ENC) + $(NONCE) using $(KEY)"
	@echo "  make decrypt         - decrypt $(ENC) + $(NONCE) to stdout using $(KEY)"
	@echo "  make roundtrip       - end-to-end self-test in a temp directory"
	@echo "  make serve           - serve the browser decrypt page at http://localhost:8000"
	@echo "  make test-web        - cross-verify the JS decoder against the Python encoder"
	@echo "  make clean           - remove $(KEY), $(ENC), $(NONCE) (keeps $(PLAIN))"

keygen:
	$(PY) keygen --out $(KEY)
	@echo "Wrote $(KEY) - keep it secret, share via email/Signal."

encrypt: $(KEY) $(PLAIN)
	$(PY) encrypt --key $(KEY) --input $(PLAIN) --out $(ENC) --nonce-out $(NONCE)
	@echo "Wrote $(ENC) ($$(wc -c < $(ENC)) bytes) and $(NONCE)."

decrypt: $(KEY) $(ENC) $(NONCE)
	@$(PY) decrypt --key $(KEY) --input $(ENC) --nonce $(NONCE)

roundtrip:
	@d=$$(mktemp -d) && \
	  $(PY) keygen --out $$d/key && \
	  printf 'Hello from somewhere sunny.\nTesting the postcard pipeline end-to-end.\n' > $$d/msg && \
	  $(PY) encrypt --key $$d/key --input $$d/msg --out $$d/enc --nonce-out $$d/nonce && \
	  echo "--- nonce ---" && cat $$d/nonce && \
	  echo "--- ciphertext ---" && cat $$d/enc && \
	  $(PY) decrypt --key $$d/key --input $$d/enc --nonce $$d/nonce --out $$d/dec && \
	  echo "--- decrypted ---" && cat $$d/dec && \
	  diff -q $$d/msg $$d/dec && echo "OK roundtrip passed" && \
	  rm -rf $$d

serve:
	@echo "Open http://localhost:8000 in your browser (Ctrl-C to stop)"
	@python3 -m http.server 8000 --bind 127.0.0.1 --directory web

test-web:
	@cd web && node test.mjs

clean:
	rm -f $(KEY) $(ENC) $(NONCE)
