import os
import sys

from shutil import copyfile
from pathlib import Path

EXCLUDED_FOLDERS = ["__pycache__", "DTOs", "tii_reports"]
EXCLUDED_FILES = ["__init__.py", "constants.py", ".DS_Store", "name_mappings.py", "finalAnalysisReportExample.txt"]
EXCLUDED_EXTENSIONS = [".md"]
ROOT_FOLDER = "../claasp/"
SOURCE_ROOT_FOLDER = "./source/"
Path(SOURCE_ROOT_FOLDER).mkdir(exist_ok=True)

IS_HTML = sys.argv[1] == "html"
REFERENCES_EXTENSION = "rst" if IS_HTML else "bib"
copyfile("conf.py", Path("source", "conf.py"))
copyfile("references.rst", Path("source", f"references.{REFERENCES_EXTENSION}"))


def header_style(section, level):
    if not section:
        return ""

    sections = {0: "=", 1: "-", 2: "=", 3: "-", 4: "`", 5: "'", 6: ".", 7: "~", 8: "*", 9: "+", 10: "^"}
    style = sections[level] * len(section)

    if level in (0, 1):
        return f"{style}\n{section}\n{style}\n"

    if level in (2, 3, 4, 5, 6, 7, 8, 9, 10):
        return f"{section}\n{style}\n"

    return section


with Path(SOURCE_ROOT_FOLDER, "index.rst").open(mode="w") as index_rst_file:
    index_rst_file.write(
        "=========================\n"
        "CLAASP: Cryptographic Library for Automated Analysis of Symmetric Primitives\n"
        "=========================\n"
        "\n"
        "This is a sample reference manual for CLAASP.\n"
        "\n"
        "To use this module, you need to import it: \n\n"
        "    from claasp import *\n\n"
        "This reference shows a minimal example of documentation of \n"
        "CLAASP following SageMath guidelines.\n"
    )

    for root, directories, files in os.walk(ROOT_FOLDER):
        path = root.split(os.sep)
        folder_name = os.path.basename(root).replace("_", " ").capitalize()
        if os.path.basename(root) not in EXCLUDED_FOLDERS:
            rst_folder = root.replace(ROOT_FOLDER, SOURCE_ROOT_FOLDER)
            Path(rst_folder).mkdir(exist_ok=True)
            index_rst_file.write(f"{header_style(folder_name, len(path) - 1)}\n")
            index_rst_file.write(".. toctree::\n\n")
            for file in files:
                file_name = os.path.splitext(file)[0]
                file_extension = os.path.splitext(file)[1]
                if file not in EXCLUDED_FILES and file_extension not in EXCLUDED_EXTENSIONS:
                    file_without_extension = os.path.splitext(file)[0]
                    file_path = os.path.join(root, file_without_extension)
                    index_rst_file.write(f"    {file_path.replace(ROOT_FOLDER, '')}\n")
                    with Path(rst_folder, file_name + ".rst").open(mode="w") as rst_file:
                        file_header = file_name.replace("_", " ").capitalize()
                        adornment = "=" * len(file_header)
                        link = file_path.replace("../claasp/", "").replace("/", ".")
                        rst_file.write(
                            f"{header_style(file_header, 1)}\n"
                            f".. automodule:: {link}\n"
                            "   :members:\n"
                            "   :undoc-members:\n"
                            "   :inherited-members:\n"
                            "   :show-inheritance:\n\n"
                        )
            index_rst_file.write("\n")

    if IS_HTML:
        index_rst_file.write(
            "\n\n"
            "General Information\n"
            "===================\n"
            "\n"
            "* :ref:`Bibliographic References <references>`\n"
            "\n"
            "Indices and Tables\n"
            "==================\n"
            "\n"
            "* :ref:`genindex`\n"
            "* :ref:`modindex`\n"
            "* :ref:`search`\n"
        )
    else:
        index_rst_file.write(".. include:: references.bib")
