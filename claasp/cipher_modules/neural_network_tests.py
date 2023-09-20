# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


import os
import secrets
import random
import numpy as np

from math import sqrt
from claasp.cipher_modules import evaluator
from keras.callbacks import ModelCheckpoint


def neural_network_blackbox_distinguisher_tests(cipher, nb_samples=10000,
                                                hidden_layers=[32, 32, 32], number_of_epochs=10, rounds_to_train=[]):
    results = {
        "neural_network_blackbox_distinguisher_tests": {
            "input_parameters": {
                "number_of_samples": nb_samples,
                "hidden_layers": hidden_layers,
                "number_of_epochs": number_of_epochs}}}
    results["neural_network_blackbox_distinguisher_tests"]["test_results"] = {}
    input_tags = cipher.inputs

    for index, input_tag in enumerate(input_tags):
        results["neural_network_blackbox_distinguisher_tests"]["test_results"][input_tag] = {}

        labels = np.frombuffer(os.urandom(nb_samples), dtype=np.uint8)
        labels = labels & 1

        base_inputs = [secrets.randbits(i) for i in cipher.inputs_bit_size]
        base_output = evaluator.evaluate(cipher, base_inputs, intermediate_output=True)[1]

        partial_result, ds, component_output_ids = create_structure(base_output, cipher, index)
        update_component_output_ids(cipher, component_output_ids)
        update_blackbox_distinguisher_vectorized_tests_ds(base_inputs, base_output, cipher, ds, index, labels, nb_samples)
        update_partial_result(cipher, component_output_ids, ds, index, hidden_layers,
                              labels, number_of_epochs, partial_result, rounds_to_train=rounds_to_train)

        results["neural_network_blackbox_distinguisher_tests"]["test_results"][input_tag].update(partial_result)

    return results


def update_partial_result(cipher, component_output_ids, ds, index, hidden_layers, labels, number_of_epochs,
                          partial_result, blackbox=True, rounds_to_train=[]):
    # noinspection PyUnresolvedReferences
    input_lengths = cipher.inputs_bit_size
    if rounds_to_train:
        assert all([r < cipher.number_of_rounds for r in rounds_to_train]), "Rounds to train don't match the number of rounds of the cipher"

    for k in ds:
        for i in range(len(ds[k][1])):
            if rounds_to_train and cipher.get_round_from_component_id(component_output_ids[k][i]) not in rounds_to_train:
                continue
            m = make_resnet(input_lengths[index] + ds[k][0] if blackbox else 2 * ds[k][0])
            m.compile(loss='binary_crossentropy', optimizer="adam", metrics=['binary_accuracy'])
            history = m.fit(np.array(ds[k][1][i]), labels, validation_split=0.1, shuffle=1, verbose=0) if blackbox \
                else m.fit(np.array(ds[k][1][i]), labels, epochs=number_of_epochs,
                           validation_split=0.1, shuffle=1, verbose=0)
            partial_result[k]["accuracies"].append({
                "value_accuracy": history.history['val_binary_accuracy'][-1],
                "round": cipher.get_round_from_component_id(component_output_ids[k][i]),
                "component_output_id": component_output_ids[k][i]})
        # print(partial_result)


def update_blackbox_distinguisher_tests_ds(base_inputs, base_output, cipher, ds, index, labels, nb_samples):
    input_lengths = cipher.inputs_bit_size
    iteration_base = base_output

    for i in range(nb_samples):
        base_inputs[index] = secrets.randbits(input_lengths[index])
        if labels[i] == 1:
            iteration_base = evaluator.evaluate(cipher, base_inputs, intermediate_output=True)[1]
        for k in iteration_base:
            for j in range(len(iteration_base[k])):
                if labels[i] == 1:
                    ds[k][1][j].append(np.array(
                        list(map(int, list(bin(base_inputs[index])[2:].rjust(input_lengths[index], '0')))) +
                        list(map(int, list(bin(iteration_base[k][j])[2:].rjust(ds[k][0], '0')))),
                        dtype=np.float32))
                else:
                    ds[k][1][j].append(np.array(
                        list(map(int, list(bin(base_inputs[index])[2:].rjust(input_lengths[index], '0')))) +
                        list(map(int, list(bin(secrets.randbits(ds[k][0]))[2:].rjust(ds[k][0], '0')))),
                        dtype=np.float32))


def update_blackbox_distinguisher_vectorized_tests_ds(base_inputs, base_output, cipher, ds, index, labels, nb_samples):
    input_lengths = cipher.inputs_bit_size
    random_labels_size = nb_samples - np.count_nonzero(np.array(labels))
    #cipher_output = base_output

    base_inputs_np = [np.broadcast_to(
        np.array([b for b in x.to_bytes(input_lengths[i] // 8, byteorder='big')], dtype=np.uint8),
        (nb_samples, input_lengths[i] // 8)
    ).transpose().copy() for i,x in enumerate(base_inputs)]
    random_inputs_for_index = np.frombuffer(os.urandom(nb_samples * input_lengths[index] // 8), dtype=np.uint8).reshape(nb_samples, input_lengths[index] // 8).transpose()
    base_inputs_np[index] = random_inputs_for_index
    base_input_index_unpacked = np.unpackbits(base_inputs_np[index].transpose(), axis=1)

    cipher_output = evaluator.evaluate_vectorized(cipher, base_inputs_np, intermediate_outputs=True)

    for k in cipher_output:
        for j in range(len(cipher_output[k])):
            output_size = len(cipher_output[k][j][0])
            cipher_output[k][j][labels==0] = np.frombuffer(os.urandom(random_labels_size * output_size), dtype=np.uint8).reshape(random_labels_size, output_size)
            cipher_output_unpacked = np.unpackbits(cipher_output[k][j], axis=1)

            full_output = np.append(base_input_index_unpacked, cipher_output_unpacked, axis=1)
            ds[k][1][j].extend(list(full_output))


def update_component_output_ids(cipher, component_output_ids):
    for k in component_output_ids:
        for component in cipher.get_all_components():
            if k in component.description:
                component_output_ids[k].append(component.id)


def create_structure(base_output, cipher, index):
    partial_result = {}
    ds = {}
    component_output_ids = {}

    for k in base_output:
        tmp_len = cipher.output_bit_size
        for component in cipher.get_all_components():
            if k in component.description:
                tmp_len = component.output_bit_size
                break
        partial_result[k] = {
            "input_bit_size": cipher.inputs_bit_size[index],
            "output_bit_size": cipher.output_bit_size,
            "max_accuracy_value": 1,
            "min_accuracy_value": 0,
            "accuracies": []}
        ds[k] = (tmp_len, [[] for _ in range(len(base_output[k]))])
        component_output_ids[k] = []

    return partial_result, ds, component_output_ids


def neural_network_differential_distinguisher_tests(cipher, nb_samples=10000, hidden_layers=[32, 32, 32],
                                                    number_of_epochs=10, diff=[0x01], rounds_to_train=[]):
    results = {
        "neural_network_differential_distinguisher_tests": {
            "input_parameters": {
                "number_of_samples": nb_samples,
                "input_differences": diff,
                "hidden_layers": hidden_layers,
                "number_of_epochs": number_of_epochs}}}
    results["neural_network_differential_distinguisher_tests"]["test_results"] = {}

    for index, it in enumerate(cipher.inputs):
        results["neural_network_differential_distinguisher_tests"]["test_results"][it] = {}

        labels = np.frombuffer(os.urandom(nb_samples), dtype=np.uint8)
        labels = labels & 1

        base_inputs = [secrets.randbits(i) for i in cipher.inputs_bit_size]
        base_output = evaluator.evaluate(cipher, base_inputs, intermediate_output=True)[1]
        for d in diff:
            partial_result, ds, component_output_ids = create_structure(base_output, cipher, index)
            update_component_output_ids(cipher, component_output_ids)
            update_distinguisher_vectorized_tests_ds(base_inputs, cipher, d, ds, index, labels, nb_samples)
            update_partial_result(cipher, component_output_ids, ds, index, hidden_layers, labels,
                                  number_of_epochs, partial_result, blackbox=False, rounds_to_train=rounds_to_train)

            results["neural_network_differential_distinguisher_tests"]["test_results"][it][d] = {}
            results["neural_network_differential_distinguisher_tests"]["test_results"][it][d].update(partial_result)

    return results


def update_distinguisher_tests_ds(base_inputs, cipher, d, ds, index, labels, nb_samples):
    input_lengths = cipher.inputs_bit_size
    for i in range(nb_samples):
        base_inputs[index] = secrets.randbits(input_lengths[index])
        other_inputs = base_inputs.copy()
        other_inputs[index] ^= d
        cipher_output = evaluator.evaluate(cipher, base_inputs, intermediate_output=True)[1]
        for k in cipher_output:
            for j in range(len(cipher_output[k])):
                if labels[i] == 1:
                    other_output = evaluator.evaluate(cipher, other_inputs, intermediate_output=True)[1]
                    ds[k][1][j] \
                        .append(np.array(list(map(int, list(bin(cipher_output[k][j])[2:].rjust(ds[k][0], '0')))) +
                                         list(map(int, list(bin(other_output[k][j])[2:].rjust(ds[k][0], '0')))),
                                         dtype=np.float32))
                else:
                    ds[k][1][j] \
                        .append(np.array(list(map(int, list(bin(cipher_output[k][j])[2:].rjust(ds[k][0], '0')))) +
                                         list(map(int, list(bin(secrets.randbits(ds[k][0]))[2:].rjust(ds[k][0], '0')))),
                                         dtype=np.float32))
                    

def update_distinguisher_vectorized_tests_ds(base_inputs, cipher, d, ds, index, labels, nb_samples):
    input_lengths = cipher.inputs_bit_size
    random_labels_size = nb_samples - np.count_nonzero(np.array(labels))

    base_inputs_np = [np.broadcast_to(
        np.array([b for b in x.to_bytes(input_lengths[i] // 8, byteorder='big')], dtype=np.uint8),
        (nb_samples, input_lengths[i] // 8)
    ).transpose().copy() for i,x in enumerate(base_inputs)]
    random_inputs_for_index = np.frombuffer(os.urandom(nb_samples * input_lengths[index] // 8), dtype=np.uint8).reshape(nb_samples, input_lengths[index] // 8).transpose()
    base_inputs_np[index] = random_inputs_for_index

    other_inputs_np = list(base_inputs_np)
    d_array = np.array([b for b in d.to_bytes(input_lengths[index] // 8, byteorder='big')])
    other_inputs_np[index] = other_inputs_np[index] ^ np.broadcast_to(d_array, (nb_samples, input_lengths[index] // 8)).transpose()

    cipher_output = evaluator.evaluate_vectorized(cipher, base_inputs_np, intermediate_outputs=True)
    other_output = evaluator.evaluate_vectorized(cipher, other_inputs_np, intermediate_outputs=True)

    for k in cipher_output:
        for j in range(len(cipher_output[k])):
            output_size = len(cipher_output[k][j][0])
            other_output[k][j][labels==0] = np.frombuffer(os.urandom(random_labels_size * output_size), dtype=np.uint8).reshape(random_labels_size, output_size)
            cipher_output_unpacked = np.unpackbits(cipher_output[k][j], axis=1)
            other_output_unpacked = np.unpackbits(other_output[k][j], axis=1)

            full_output = np.append(cipher_output_unpacked, other_output_unpacked, axis=1)
            ds[k][1][j].extend(list(full_output))


def integer_to_np(val, number_of_bits):
    return np.frombuffer(int(val).to_bytes(length=number_of_bits // 8, byteorder='big'), dtype=np.uint8).reshape(-1, 1)


def get_differential_dataset(cipher, input_differences, number_of_rounds, samples=10 ** 7):
    from os import urandom
    inputs_0 = []
    inputs_1 = []
    y = np.frombuffer(urandom(samples), dtype=np.uint8) & 1
    num_rand_samples = np.sum(y == 0)
    for i, inp in enumerate(cipher.inputs):
        inputs_0.append(np.frombuffer(urandom(samples * (cipher.inputs_bit_size[i] // 8)),
                                      dtype=np.uint8).reshape(-1, samples))  # requires input size to be a multiple of 8
        inputs_1.append(inputs_0[-1] ^ integer_to_np(input_differences[i], cipher.inputs_bit_size[i]))
        inputs_1[-1][:, y == 0] ^= np.frombuffer(urandom(num_rand_samples * cipher.inputs_bit_size[i] // 8),
                                                 dtype=np.uint8).reshape(-1, num_rand_samples)

    C0 = np.unpackbits(cipher.evaluate_vectorized(inputs_0, intermediate_outputs=True)['round_output'][number_of_rounds - 1], axis=1)
    C1 = np.unpackbits(cipher.evaluate_vectorized(inputs_1, intermediate_outputs=True)['round_output'][number_of_rounds - 1], axis=1)
    x = np.hstack([C0, C1])
    return x, y


def get_neural_network(network_name, input_size, word_size = None):
    from tensorflow.keras.optimizers import Adam
    if network_name == 'gohr_resnet':
        neural_network = make_resnet(word_size = word_size, input_size = input_size)
    elif network_name == 'dbitnet':
        neural_network = make_dbitnet(input_size = input_size)
    neural_network.compile(optimizer=Adam(amsgrad=True), loss='mse', metrics=['acc'])
    return neural_network


def make_checkpoint(datei):
    res = ModelCheckpoint(datei, monitor='val_loss', save_best_only=True)
    return res


def train_neural_distinguisher(cipher, data_generator, starting_round, neural_network, training_samples=10 ** 7,
                           testing_samples=10 ** 6, num_epochs=1):
    acc = 1
    bs = 5000
    x, y = data_generator(samples = training_samples, nr = starting_round)
    x_eval, y_eval = data_generator(samples = testing_samples, nr = starting_round)
    h = neural_network.fit(x, y, epochs=num_epochs, batch_size=bs, validation_data=(x_eval, y_eval))
    acc = np.max(h.history["val_acc"])
    print(f'Validation accuracy at {starting_round} rounds :{acc}')
    return acc


def neural_staged_training(cipher, data_generator, starting_round, neural_network=None, training_samples=10 ** 7,
                           testing_samples=10 ** 6, num_epochs=1):
    acc = 1
    nr = starting_round
    # threshold at 10 sigma
    threshold = 0.5 + 10 * sqrt(testing_samples//4)/testing_samples
    accuracies = {}
    while acc >= threshold and nr < cipher.number_of_rounds:
        acc = train_neural_distinguisher(cipher, data_generator, nr, neural_network, training_samples, testing_samples, num_epochs)
        accuracies[nr] = acc
        nr += 1
    return accuracies

def make_resnet(input_size, num_filters=32, num_outputs=1, d1=64, d2=64, word_size=16, ks=3, reg_param=10 ** -5,
                final_activation='sigmoid', depth=1):
    from keras.models import Model
    from keras.layers import Dense, Conv1D, Input, Reshape, Permute, Add, Flatten, BatchNormalization, Activation
    from keras import backend as K
    from keras.regularizers import l2
    # Input and preprocessing layers
    inp = Input(shape=(input_size,))
    rs = Reshape((input_size//word_size, word_size))(inp)
    perm = Permute((2, 1))(rs)
    # add a single residual layer that will expand the data to num_filters channels
    # this is a bit-sliced layer
    conv0 = Conv1D(num_filters, kernel_size=1, padding='same', kernel_regularizer=l2(reg_param))(perm)
    conv0 = BatchNormalization()(conv0)
    conv0 = Activation('relu')(conv0)
    # add residual blocks
    shortcut = conv0
    for _ in range(depth):
        conv1 = Conv1D(num_filters, kernel_size=ks, padding='same', kernel_regularizer=l2(reg_param))(shortcut)
        conv1 = BatchNormalization()(conv1)
        conv1 = Activation('relu')(conv1)
        conv2 = Conv1D(num_filters, kernel_size=ks, padding='same', kernel_regularizer=l2(reg_param))(conv1)
        conv2 = BatchNormalization()(conv2)
        conv2 = Activation('relu')(conv2)
        shortcut = Add()([shortcut, conv2])
    # add prediction head
    flat1 = Flatten()(shortcut)
    dense1 = Dense(d1, kernel_regularizer=l2(reg_param))(flat1)
    dense1 = BatchNormalization()(dense1)
    dense1 = Activation('relu')(dense1)
    dense2 = Dense(d2, kernel_regularizer=l2(reg_param))(dense1)
    dense2 = BatchNormalization()(dense2)
    dense2 = Activation('relu')(dense2)
    out = Dense(num_outputs, activation=final_activation, kernel_regularizer=l2(reg_param))(dense2)
    model = Model(inputs=inp, outputs=out)
    return (model)

def make_dbitnet(input_size=64, n_filters=32, n_add_filters=16):
    """Create a DBITNet model.

    :param input_size: e.g. for SPECK32/64 and 2 ciphertexts, the input_size is 64 bit.
    :return: DBitNet model.
    """
    def get_dilation_rates(input_size):
        """Helper function to determine the dilation rates of DBitNet given an input_size. """
        drs = []
        while input_size >= 8:
            drs.append(int(input_size / 2 - 1))
            input_size = input_size // 2

        return drs

    import tensorflow as tf
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Conv1D, Dense, Dropout, Lambda, concatenate, BatchNormalization, \
            Activation, Add
    from tensorflow.keras.regularizers import l2

    # determine the dilation rates from the given input size
    dilation_rates = get_dilation_rates(input_size)

    # prediction head parameters (similar to Gohr)
    d1 = 256
    d2 = 64
    reg_param = 1e-5

    # define the input shape
    inputs = Input(shape=(input_size, 1))
    x = inputs

    # normalize the input data to a range of [-1, 1]:
    x = tf.subtract(x, 0.5)
    x = tf.divide(x, 0.5)

    for dilation_rate in dilation_rates:
        ### wide-narrow blocks
        x = Conv1D(filters=n_filters,
                   kernel_size=2,
                   padding='valid',
                   dilation_rate=dilation_rate,
                   strides=1,
                   activation='relu')(x)
        x = BatchNormalization()(x)
        x_skip = x
        x = Conv1D(filters=n_filters,
                   kernel_size=2,
                   padding='causal',
                   dilation_rate=1,
                   activation='relu')(x)
        x = Add()([x, x_skip])
        x = BatchNormalization()(x)

        n_filters += n_add_filters

    ### prediction head
    out = tf.keras.layers.Flatten()(x)
    dense0 = Dense(d1, kernel_regularizer=l2(reg_param))(out);
    dense0 = BatchNormalization()(dense0);
    dense0 = Activation('relu')(dense0);
    dense1 = Dense(d1, kernel_regularizer=l2(reg_param))(dense0);
    dense1 = BatchNormalization()(dense1);
    dense1 = Activation('relu')(dense1);
    dense2 = Dense(d2, kernel_regularizer=l2(reg_param))(dense1);
    dense2 = BatchNormalization()(dense2);
    dense2 = Activation('relu')(dense2);
    out = Dense(1, activation='sigmoid', kernel_regularizer=l2(reg_param))(dense2)
    model = Model(inputs, out)
    return model


def find_good_input_difference_for_neural_distinguisher(cipher, difference_positions,
                                                        initial_population=32, number_of_generations=15,
                                                        nb_samples=10 ** 3, previous_generation=None, verbose=False):
    # Initialisation
    input_lengths = cipher.inputs_bit_size
    input_tags = cipher.inputs
    evaluate = lambda x: cipher.evaluate_vectorized(x, intermediate_outputs=True)
    threshold = 0.05
    # Generation of the baseline ciphertexts
    inputs0 = []
    num_input_bits = 0
    for i in range(len(input_tags)):
        inputs0.append(np.random.randint(256, size=(input_lengths[i] // 8, nb_samples), dtype=np.uint8))
        if difference_positions[i]:
            num_input_bits += input_lengths[i]
    C0 = evaluate(inputs0)['round_output']
    diffs, scores, highest_round = evolutionary_algorithm(previous_generation, initial_population,
                                                          number_of_generations, verbose,
                                                          difference_evaluation_function=lambda
                                                          x: evaluate_multiple_differences(input_lengths,
                                                                                           difference_positions,
                                                                                           evaluate, x, inputs0, C0,
                                                                                           threshold),
                                                          difference_bits=num_input_bits)
    if verbose:
        print("The highest reached round was", highest_round)
        print("The best differences found by the optimizer are...")
        for i in range(1, 11):
            print(hex(diffs[-i]), ", with score", scores[-i])
    return diffs, scores, highest_round


def evolutionary_algorithm(previous_generation, initial_population, number_of_generations, verbose,
                           difference_evaluation_function, difference_bits):
    mut_prob = 0.1
    if previous_generation is None:
        generation = np.array([random.randint(1, 1 << difference_bits)
                               for _ in range(initial_population)], dtype=object)
        # Restored randint instead of secrets. secrets.choice has a bound on max value,
        # while randint does not, and we sometimes need 64+ bit integers here
        # generation = np.array([secrets.choice(range(1, 1 << difference_bits))
        #                       for _ in range(initial_population ** 2)], dtype=object)
    else:
        generation = previous_generation
    scores, highest_round = difference_evaluation_function(generation)
    idx = np.arange(len(generation))
    explored = np.copy(generation)
    best_differences = idx[np.argsort(scores)][-initial_population:]
    generation = generation[best_differences]

    scores = scores[best_differences]
    cpt = initial_population ** 2
    for i in range(number_of_generations):
        # New generation
        kids = np.array([a ^ b for a in generation for b in generation if a != b], dtype=object)
        # Mutation: selecting mutating kids
        selected_for_mutation = np.random.randint(0, 100, len(kids))
        number_to_mutate = np.sum(selected_for_mutation >= 100 * (1 - mut_prob))
        # Selected kids are XORed with 1<<r (r random)
        kids[selected_for_mutation >= 100 * (1 - mut_prob)] ^= \
            (np.array(1, dtype=object) << np.random.randint(0, difference_bits - 1, number_to_mutate))
        # Removing kids that have been explored before, duplicates, and 0 values
        kids = np.unique(np.setdiff1d(kids, explored))

        # Appending to explored
        kids = kids[kids != 0]
        explored = np.append(explored, kids)
        cpt += len(kids)
        # Computing the scores
        if len(kids) > 0:
            tmp_scores, tmp_highest_round = difference_evaluation_function(kids)
            scores = np.append(scores, tmp_scores)
            generation = np.append(generation, kids)
            if highest_round < tmp_highest_round:
                highest_round = tmp_highest_round
            # Sorting, keeping only the L best ones
            idx = np.arange(len(generation))
            best_l_differences = idx[np.argsort(scores)][-initial_population:]
            generation = generation[best_l_differences]
            scores = scores[best_l_differences]
        if verbose:
            print(
                f'Generation {i}/{number_of_generations}, {cpt} nodes explored, {len(generation)} '
                f'current, best is {[hex(x) for x in generation[-4:]]} with {scores[-4:]}',
                flush=True)

    return generation, scores, highest_round


def evaluate_multiple_differences(input_lengths, difference_positions, encrypt, candidate_differences, inputs0, c0,
                                  threshold):
    inputs1 = [None for _ in inputs0]
    formatted_differences, number_of_differences = format_difference(input_lengths, difference_positions,
                                                                     candidate_differences)
    for input_index in range(len(difference_positions)):
        difference_in_input = formatted_differences[input_index]
        if difference_positions[input_index]:
            inputs1[input_index] = (difference_in_input[:, :, None] ^ inputs0[input_index][:, None, :]) \
                .reshape(inputs0[input_index].shape[0], -1)
        else:
            inputs1[input_index] = np.tile(inputs0[input_index], number_of_differences)
    round_outputs = encrypt(inputs1)['round_output']
    scores = 0
    for i in range(1, len(round_outputs)):
        nr = i - 1
        C1 = round_outputs[nr]
        differences_in_output = C1.reshape(number_of_differences, c0[nr].shape[0], c0[nr].shape[1]) ^ c0[nr]
        binary_differences = np.unpackbits(differences_in_output, axis=2)
        bit_scores_per_diff = np.abs(0.5 - np.average(binary_differences, axis=1))
        round_scores = np.average(bit_scores_per_diff, axis=1)
        scores += i * round_scores
        if np.max(round_scores) < threshold:
            break

    return scores, i


def format_difference(input_lengths, difference_positions, differences=None):
    # Splits a difference received as an integer into differences for each input that needs one
    # num_bytes = np.sum(input_lengths[difference_positions==True]) // 8
    num_bytes = 0
    for i in range(len(input_lengths)):
        if difference_positions[i]:
            num_bytes += input_lengths[i] // 8
    # num_bytes = np.sum(x for x in input_lengths if difference_positions==True]) // 8
    numpy_differences = np.uint8([(differences >> ((num_bytes - i - 1) * 8)) & 0xffff
                                  for i in range(num_bytes)]).reshape((num_bytes, -1))
    taken = 0
    number_of_differences = 0
    formatted_differences = []
    for i in range(len(difference_positions)):
        if difference_positions[i]:
            to_take = input_lengths[i] // 8
            formatted_differences.append(numpy_differences[taken:taken + to_take])
            taken += to_take
            number_of_differences = len(differences)
        else:
            formatted_differences.append(0)

    return formatted_differences, number_of_differences
