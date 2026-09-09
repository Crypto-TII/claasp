SPHINXBUILD ?= sphinx-build
SOURCEDIR = .
BUILDDIR = _build

.PHONY: html doctest clean

html:
	$(SPHINXBUILD) -W --keep-going -b html $(SOURCEDIR) $(BUILDDIR)/html

doctest:
	$(SPHINXBUILD) -W --keep-going -b doctest $(SOURCEDIR) $(BUILDDIR)/doctest

clean:
	$(SPHINXBUILD) -M clean $(SOURCEDIR) $(BUILDDIR)
