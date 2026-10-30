from io import BytesIO

import pytest

from claasp.analysis import SuppliedStatisticalDataset


def test_supplied_bit_stream_is_immutable_and_msb_first():
    bits = [1, 0, 1, 0, 1, 0, 1, 1, 1]
    dataset = SuppliedStatisticalDataset.from_bits(bits)
    bits[0] = 0
    assert dataset.data == b"\xab\x80"
    assert dataset.bit_count == 9
    output = BytesIO()
    assert dataset.write_binary(output) == 2
    assert output.getvalue() == dataset.data
    import hashlib

    assert dataset.digest() == hashlib.sha256(output.getvalue()).hexdigest()


@pytest.mark.parametrize("bits", [[], [2], [-1], [0.5], [[0, 1]], ["0"]])
def test_supplied_bits_reject_invalid_input(bits):
    with pytest.raises(ValueError):
        SuppliedStatisticalDataset.from_bits(bits)


def test_supplied_files_use_explicit_formats(tmp_path):
    path = tmp_path / "data"
    path.write_bytes(b"10\n10 11\t01")
    assert SuppliedStatisticalDataset.from_file(path, input_format="ascii").data == b"\xad"
    assert SuppliedStatisticalDataset.from_file(path).data == path.read_bytes()
    path.write_bytes(b"101x")
    with pytest.raises(ValueError):
        SuppliedStatisticalDataset.from_file(path, input_format="ascii")
    with pytest.raises(ValueError):
        SuppliedStatisticalDataset.from_file(path, input_format="guess")


def test_supplied_numpy_bits():
    np = pytest.importorskip("numpy")
    dataset = SuppliedStatisticalDataset.from_bits(np.array([0, 1] * 4, dtype=np.uint8))
    assert dataset.data == b"\x55"


@pytest.mark.parametrize("data,count", [(b"", 0), (b"\xff", 7), (b"\x00\x00", 1), (b"\x00", True)])
def test_supplied_packing_validation(data, count):
    with pytest.raises(ValueError):
        SuppliedStatisticalDataset(data, count)
