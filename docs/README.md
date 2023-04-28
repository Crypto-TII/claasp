# Documentation guidelines

## Adding a reference item

Adding a new reference item should follow some simple rules.

* Label: if the item is by one author, take the first three letters of
  the surname, capitalize the first and add the year in format yyyy; if
  the paper is by more than one author, take the initial letter
  capitalized of every surname and add year in format yyyy.

* Authors: the format is `Surname N.`, if more than one author,
  separate them by comma.

* Title: the format is `\*Title\*`.

* Additional information: any format (editor, year, ...).

* Link: if any.

* Separate Authors, Title, Additional information, Link using the
  string " : ".

***REMARK***: some labels do not follow the rule because they are inherited
from Sage. Therefore, their format is mandatory.

## Excluding some modules

When programming in Python and following good practices *(hopefully the best
ones)*, sometimes, files like `constants.py` are added, and they do not need to
be documented. When a file do not need to be documented, it has to be added in 
`EXCLUDED_FILES` constant inside `create_rst_structure.py` file.

## Methods excluded

Remeber that methods whose name starts with at least one `_` are not
automatically documented.
