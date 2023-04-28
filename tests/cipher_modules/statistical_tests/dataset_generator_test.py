from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator

numpy_array_type = "<class 'numpy.ndarray'>"


def test_generate_avalanche_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_avalanche_dataset(input_index=0, number_of_samples=2)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type


def test_generate_cbc_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_cbc_dataset(input_index=0, number_of_samples=2,
                                                     number_of_blocks_in_one_sample=10)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type


def test_generate_correlation_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_correlation_dataset(input_index=0, number_of_samples=2,
                                                             number_of_blocks_in_one_sample=10)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type


def test_generate_high_density_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_high_density_dataset(input_index=0, number_of_samples=2, ratio=0.5)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type


def test_generate_low_density_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_low_density_dataset(input_index=0, number_of_samples=2, ratio=0.5)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type


def test_generate_random_dataset():
    dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
    dataset = dataset_generator.generate_random_dataset(input_index=0, number_of_samples=2,
                                                        number_of_blocks_in_one_sample=10)

    assert len(dataset) == 3
    assert str(type(dataset[0])) == numpy_array_type
    assert str(type(dataset[2])) == numpy_array_type
