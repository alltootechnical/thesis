LATEX=latexmk
LFLAGS=-pdf -pdflatex="pdflatex -interaction=nonstopmode -file-line-error" -bibtex -f -g -use-make
BIB=bibtex

TEXFILE=thesis
#TEXFILE=FinalManuscript_orig
BIBFILE=thesis_refs.bib

all: thesis
.PHONY: clean thesis

thesis: thesis_refs.bib $(TEXFILE).tex
	-$(LATEX) $(LFLAGS) $(TEXFILE).tex
reftest: thesis_refs.bib reftest.tex
	$(LATEX) $(LFLAGS) reftest.tex
	
clean:
	rm -f *.aux
	rm -f *.bbl
	rm -f *.blg
	rm -f *.idx
	rm -f *.log
	rm -f *.out
	rm -f *.lof
	rm -f *.lot
	rm -f *.toc
	rm -f *.fdb_latexmk
	rm -f *.fls
	rm -f *.synctex.gz
	echo "Removed temporary files"
	
