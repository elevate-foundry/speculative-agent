# Makefile for Speculative Agent paper
# Targets: pdf (requires BasicTeX), html (requires pandoc), clean

MAIN = main
TEX  = $(MAIN).tex
BIB  = refs.bib

.PHONY: pdf html both clean install-tex

# ── PDF via pdflatex + bibtex (requires BasicTeX / MacTeX) ─────────────────
pdf: $(TEX) $(BIB)
	pdflatex $(MAIN)
	bibtex $(MAIN)
	pdflatex $(MAIN)
	pdflatex $(MAIN)
	@echo "\n✓ Built $(MAIN).pdf"

# ── HTML via pandoc (available now) ────────────────────────────────────────
html: $(TEX) $(BIB)
	pandoc $(TEX) \
	  --bibliography=$(BIB) \
	  --citeproc \
	  --standalone \
	  --mathjax \
	  --toc \
	  --metadata title="Speculative Agent" \
	  -o $(MAIN).html
	@echo "\n✓ Built $(MAIN).html — open with: open $(MAIN).html"

# ── Both ───────────────────────────────────────────────────────────────────
both: html pdf

# ── Clean build artifacts ──────────────────────────────────────────────────
clean:
	rm -f $(MAIN).pdf $(MAIN).html \
	      $(MAIN).aux $(MAIN).bbl $(MAIN).blg \
	      $(MAIN).log $(MAIN).out $(MAIN).toc

# ── Install BasicTeX (macOS, ~100MB) ───────────────────────────────────────
install-tex:
	brew install --cask basictex
	@echo "After install, run: sudo tlmgr update --self && sudo tlmgr install collection-latex"
