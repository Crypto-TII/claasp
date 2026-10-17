"""Render default R1 wire views and reject actual PDF label/box collisions.

Requires Sage/CLAASP, pdflatex and Poppler's pdftotext/pdftoppm. Run directly;
this optional rendering check is separate from the Python unit-test suite.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, from_ascii, to_ascii, to_tikz


def intersection(a, b):
    width = min(a[2], b[2])-max(a[0], b[0])
    height = min(a[3], b[3])-max(a[1], b[1])
    return (width, height) if width > 0.0001 and height > 0.0001 else None


def control(operation):
    c = Cipher('anonymous_detail_control', 'permutation', ['a', 'b', 'c'], [4]*3, 4)
    c.add_round()
    gate = getattr(c, 'add_'+operation+'_component')(['a', 'b', 'c', 'a'], [list(range(4))]*4, 4)
    c.add_cipher_output_component([gate.id], [list(range(4))], 4)
    return from_cipher(c)


def run(operation, directory, binaries):
    ir = control(operation)
    before = copy.deepcopy(ir)
    ascii_text = to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    assert from_ascii(ascii_text) == ir
    fragment = to_tikz(ir, layoutSource='human', view='wires', word_bits=4,
                       associative_reductions=True, legend='none')
    assert ir == before
    assert ir['nodes'][0]['description'][1] == 4
    # Probe the actual rendered node rectangles; paths add no visible content.
    names = re.findall(r'\\node\[draw,[^\n]*?\((N\d+x\d+)\) at', fragment)
    assert len(names) == 7
    measurements = '\n'.join(
        r'\path let \p1=('+name+r'.south west), \p2=('+name+r'.north east) in '
        r'\pgfextra{\typeout{DGBBOX:'+name+r':\x1:\y1:\x2:\y2}};'
        for name in names)
    fragment = fragment.replace(r'\end{tikzpicture}', measurements+'\n'+r'\end{tikzpicture}')
    tex = ('\\documentclass{article}\n\\usepackage[margin=10mm]{geometry}\n'
           '\\usepackage{tikz,amsmath,amssymb,hyperref}\n'
           '\\usetikzlibrary{arrows.meta,calc,positioning}\n'
           '\\pagestyle{empty}\n\\begin{document}\n'+fragment+'\n\\end{document}\n')
    (directory/(operation+'.tex')).write_text(tex)
    (directory/(operation+'.asciiart')).write_text(ascii_text)
    subprocess.run([binaries['pdflatex'], '-no-shell-escape', '-interaction=nonstopmode',
                    '-halt-on-error', operation+'.tex'], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, timeout=60)
    pdf = directory/(operation+'.pdf')
    bbox_path = directory/(operation+'-bbox.html')
    subprocess.run([binaries['pdftotext'], '-bbox', str(pdf), str(bbox_path)], check=True, timeout=30)
    pages = ET.parse(bbox_path).getroot().findall('.//{*}page')
    collisions = []
    for page_number, page in enumerate(pages, 1):
        words = page.findall('.//{*}word')
        refs = [word for word in words if re.fullmatch(r'D\d+:\d+', word.text or '')]
        operands = [word for word in words if word.text in ('1', '2')]
        bounds = lambda word: tuple(float(word.attrib[key]) for key in ('xMin', 'yMin', 'xMax', 'yMax'))
        for ref in refs:
            for operand in operands:
                overlap = intersection(bounds(ref), bounds(operand))
                if overlap:
                    collisions.append({'page': page_number, 'reference': ref.text,
                                       'operand': operand.text, 'overlap_pt': overlap})
    boxes = []
    for match in re.finditer(r'DGBBOX:(N\d+x\d+):([^:\n]+):([^:\n]+):([^:\n]+):([^:\n]+)',
                             (directory/(operation+'.log')).read_text()):
        coordinates = tuple(float(value.strip().removesuffix('pt')) for value in match.groups()[1:])
        boxes.append((match[1], coordinates))
    assert len(boxes) == 7
    box_collisions = []
    vertical_gaps = []
    for index, (name, box) in enumerate(boxes):
        for other_name, other in boxes[index+1:]:
            overlap = intersection(box, other)
            if overlap:
                box_collisions.append({'nodes': [name, other_name], 'overlap_pt': overlap})
            if min(box[2], other[2]) > max(box[0], other[0]):
                vertical_gaps.append(max(box[1], other[1])-min(box[3], other[3]))
    subprocess.run([binaries['pdftoppm'], '-f', str(len(pages)), '-l', str(len(pages)),
                    '-singlefile', '-png', '-scale-to', '1600', str(pdf),
                    str(directory/(operation+'-detail'))], check=True, timeout=30)
    return {'operation': operation, 'default_row_spacing_cm': 1, 'boxes': len(boxes),
            'operand_reference_collisions': collisions, 'box_collisions': box_collisions,
            'minimum_vertical_box_gap_pt': min(vertical_gaps),
            'ascii_sha256': hashlib.sha256(ascii_text.encode()).hexdigest(),
            'ir_unchanged': True, 'native_arity': 4}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--expect-overlap', action='store_true', help='Reproduce the prior regression.')
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    binaries = {name: shutil.which(name) for name in ('pdflatex', 'pdftotext', 'pdftoppm')}
    if not all(binaries.values()):
        raise SystemExit('Missing rendering dependency: '+', '.join(name for name, path in binaries.items() if not path))
    results = [run(operation, directory, binaries) for operation in ('xor', 'and', 'or', 'modadd')]
    (directory/'render-results.json').write_text(json.dumps(results, indent=2)+'\n')
    for result in results:
        overlaps = bool(result['operand_reference_collisions'] or result['box_collisions'])
        assert overlaps == args.expect_overlap, result
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
