"""Two actual routed vector overviews for local visual review (no publication).

Run with the repository on PYTHONPATH: python docs/diagrams/render_inline_constants.py OUTPUT
Then compile OUTPUT/inline-constants-review.tex with pdflatex -no-shell-escape.
Overview scaling is for review; it makes no minimum-font or geometry claim.
"""
import argparse
from pathlib import Path
from claasp.diagrams import Diagrams
from claasp.ciphers.permutations.alzette_permutation import AlzettePermutation
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=True)
    pages = []
    for title, cipher in [('Alzette, default constructor', AlzettePermutation()),
                          ('Gimli, one round', GimliPermutation(number_of_rounds=1))]:
        diagram = Diagrams(cipher)
        picture = diagram.to_tikz(routed_words=True, rowsPerPanel=1000, columnsPerPanel=1000,
                                 maxPanels=1, fitToPage=(16, 19))
        pages.append(r'\section*{'+title+'}\n'+r'\noindent Explicit routed words; actual vector overview. '
                     r'Long literals use the established upper-prefix/middle-suffix arrangement. '
                     r'The default path still rejects live-operand spill.'+'\n\n'+picture)
    document = (r'\documentclass{article}'+'\n'+r'\usepackage[a4paper,margin=2cm]{geometry}'+'\n'
                +r'\usepackage{tikz}'+'\n'+r'\begin{document}'+'\n'
                +('\n'+r'\clearpage'+'\n').join(pages)+'\n'+r'\end{document}'+'\n')
    (output/'inline-constants-review.tex').write_text(document)


if __name__ == '__main__':
    main()
