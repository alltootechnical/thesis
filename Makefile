LATEX=pdflatex
BIB=bibtex

reftest: thesis_refs.bib reftest.tex
	$(LATEX) -interaction=nonstopmode reftest.tex
	$(BIB) reftest.aux
	$(LATEX) -interaction=nonstopmode reftest.tex
	$(LATEX) -interaction=nonstopmode reftest.tex
	
