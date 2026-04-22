# Makefile for Speculative Agent paper
# Targets: pdf (requires BasicTeX), html (requires pandoc), clean

MAIN = main
TEX  = $(MAIN).tex
BIB  = refs.bib

.PHONY: pdf html both clean install-tex paper-eval

# ── PDF via pdflatex + bibtex (requires BasicTeX / MacTeX) ─────────────────
pdf: $(TEX) $(BIB)
	pdflatex $(MAIN)
	bibtex $(MAIN)
	pdflatex $(MAIN)
	pdflatex $(MAIN)
	@echo "\n✓ Built $(MAIN).pdf"

# ── HTML via pandoc (available now) ────────────────────────────────────────
html: $(TEX) $(BIB) style.css header.html
	pandoc $(TEX) \
	  --bibliography=$(BIB) \
	  --citeproc \
	  --standalone \
	  --mathjax \
	  --toc \
	  --css=style.css \
	  --include-before-body=header.html \
	  --metadata title="Speculative Racing with Tropical Compliance Lattices" \
	  --metadata "lang=en" \
	  --variable "header-includes=<link rel='canonical' href='https://elevate-foundry.github.io/speculative-agent/'>" \
	  -o $(MAIN).html
	@echo "\n✓ Built $(MAIN).html — open with: open $(MAIN).html"

# ── Both ───────────────────────────────────────────────────────────────────
both: html pdf

# ── Clean build artifacts ──────────────────────────────────────────────────
clean:
	rm -f $(MAIN).pdf $(MAIN).html \
	      $(MAIN).aux $(MAIN).bbl $(MAIN).blg \
	      $(MAIN).log $(MAIN).out $(MAIN).toc

# ── Run eval suite and auto-patch main.tex with live results ───────────────
paper-eval:
	cd .. && .venv/bin/python eval_suite.py --quiet --patch-paper
	$(MAKE) html
	@echo "\n✓ paper-eval complete — main.tex patched and HTML rebuilt"

# ── Install BasicTeX (macOS, ~100MB) ───────────────────────────────────────
install-tex:
	brew install --cask basictex
	@echo "After install, run: sudo tlmgr update --self && sudo tlmgr install collection-latex"
