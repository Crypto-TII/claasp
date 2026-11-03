from pathlib import Path

from claasp.cipher_modules.statistical_tests.nist_statistical_tests_report import NISTStatisticalTestsReport
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher


def _sample_nist_results(cipher):
    test_entry = {
        "test_id": 1,
        "test_name": "Frequency",
        "passed": True,
        "p-value": 0.5,
        "passed_seqs": 10,
        "total_seqs": 10,
        "passed_proportion": 1.0,
    }
    for i in range(1, 11):
        test_entry[f"C{i}"] = 0

    test_entry2 = {
        "test_id": 2,
        "test_name": "BlockFrequency",
        "passed": True,
        "p-value": 0.25,
        "passed_seqs": 9,
        "total_seqs": 10,
        "passed_proportion": 0.9,
    }
    for i in range(1, 11):
        test_entry2[f"C{i}"] = 0

    report = {
        "data_type": "plaintext_avalanche",
        "cipher_name": cipher.id,
        "round": 0,
        "rounds": 2,
        "passed_tests": 2,
        "number_of_sequences_threshold": [{"total": 10, "passed": 8}],
        "randomness_test": [test_entry, test_entry2],
    }

    return {
        "input_parameters": {
            "test_name": "nist_statistical_tests",
            "cipher": cipher,
            "test_type": "avalanche",
        },
        "test_results": [report],
    }


def test_generate_reports_and_charts(tmp_path):
    cipher = SimonBlockCipher(number_of_rounds=2)
    nist_results = _sample_nist_results(cipher)

    reporter = NISTStatisticalTestsReport(nist_results)
    output_dir = reporter.generate_all(output_dir=str(tmp_path))

    dataset_dir = Path(output_dir) / "plaintext_avalanche"
    round_dir = dataset_dir / "round_1"
    report_file = round_dir / "finalAnalysisReport.txt"

    assert report_file.is_file()
    assert (dataset_dir / f"nist_plaintext_avalanche_{cipher.id}_round_1.png").is_file()
    assert (dataset_dir / f"nist_plaintext_avalanche_{cipher.id}.png").is_file()
