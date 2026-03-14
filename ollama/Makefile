APPTAINER ?= apptainer
DEF_FILE ?= ollama.def
OUT_FILE ?= ollama.sif

.PHONY: build build-fakeroot build-root check-apptainer

check-apptainer:
	@command -v "$(APPTAINER)" >/dev/null 2>&1 || { echo "ERROR: $(APPTAINER) not found in PATH" >&2; exit 1; }

build: check-apptainer
	@if [ "$$(id -u)" -eq 0 ]; then \
		"$(APPTAINER)" build "$(OUT_FILE)" "$(DEF_FILE)"; \
	else \
		"$(APPTAINER)" build --fakeroot "$(OUT_FILE)" "$(DEF_FILE)"; \
	fi

build-fakeroot: check-apptainer
	"$(APPTAINER)" build --fakeroot "$(OUT_FILE)" "$(DEF_FILE)"

build-root: check-apptainer
	"$(APPTAINER)" build "$(OUT_FILE)" "$(DEF_FILE)"
