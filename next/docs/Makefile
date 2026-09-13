SPHINXBUILD ?= sphinx-build
SOURCEDIR = .
BUILDDIR = _build

.PHONY: html user-html developer-html doctest user-doctest developer-doctest clean

html: user-html developer-html

user-html:
	CLAASP_DOCS_GUIDE=user $(SPHINXBUILD) -W --keep-going -b html $(SOURCEDIR) $(BUILDDIR)/user

developer-html:
	CLAASP_DOCS_GUIDE=developer $(SPHINXBUILD) -W --keep-going -b html $(SOURCEDIR) $(BUILDDIR)/developer

doctest: user-doctest developer-doctest

user-doctest:
	CLAASP_DOCS_GUIDE=user $(SPHINXBUILD) -W --keep-going -b doctest $(SOURCEDIR) $(BUILDDIR)/user-doctest

developer-doctest:
	CLAASP_DOCS_GUIDE=developer $(SPHINXBUILD) -W --keep-going -b doctest $(SOURCEDIR) $(BUILDDIR)/developer-doctest

clean:
	$(SPHINXBUILD) -M clean $(SOURCEDIR) $(BUILDDIR)
