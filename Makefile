LATEX=pdflatex
LFLAGS=-interaction=nonstopmode
BIB=bibtex

reftest: thesis_refs.bib reftest.tex
	$(LATEX) $(LFLAGS) reftest.tex
	$(BIB) reftest.aux
	$(LATEX) $(LFLAGS) reftest.tex
	$(LATEX) $(LFLAGS) reftest.tex
	
thesis:
	echo "Wala pa..."
