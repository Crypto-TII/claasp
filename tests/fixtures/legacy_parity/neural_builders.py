"""Unmodified numerical network builders from pinned legacy CLAASP.

Source: claasp/cipher_modules/neural_network_tests.py
Commit: 1136c49f8b68fdc1839eb9df04132c99a2e05387
Only imports, the enclosing class name, an unused loop variable and formatting are adapted.
"""

import tensorflow as tf
from tensorflow.keras.layers import (
    Activation,
    Add,
    BatchNormalization,
    Conv1D,
    Dense,
    Flatten,
    Input,
    Rescaling,
)
from tensorflow.keras.models import Model
from tensorflow.keras.regularizers import l2


class LegacyNeuralBuilders:
    def _make_resnet(
        self,
        input_size,
        num_filters=32,
        num_outputs=1,
        d1=64,
        d2=64,
        word_size=16,
        ks=3,
        reg_param=10**-5,
        final_activation="sigmoid",
        depth=1,
    ):
        from tensorflow.keras.layers import (
            Activation,
            Add,
            BatchNormalization,
            Conv1D,
            Dense,
            Input,
            Permute,
            Reshape,
        )
        from tensorflow.keras.models import Model
        from tensorflow.keras.regularizers import l2

        inp = Input(shape=(input_size,))
        rs = Reshape((input_size // word_size, word_size))(inp)
        perm = Permute((2, 1))(rs)
        conv0 = Conv1D(
            num_filters, kernel_size=1, padding="same", kernel_regularizer=l2(reg_param)
        )(perm)
        conv0 = BatchNormalization()(conv0)
        conv0 = Activation("relu")(conv0)
        shortcut = conv0
        for _i in range(depth):
            conv1 = Conv1D(
                num_filters, kernel_size=ks, padding="same", kernel_regularizer=l2(reg_param)
            )(shortcut)
            conv1 = BatchNormalization()(conv1)
            conv1 = Activation("relu")(conv1)
            conv2 = Conv1D(
                num_filters, kernel_size=ks, padding="same", kernel_regularizer=l2(reg_param)
            )(conv1)
            conv2 = BatchNormalization()(conv2)
            conv2 = Activation("relu")(conv2)
            shortcut = Add()([shortcut, conv2])
        flat1 = Flatten()(shortcut)
        dense = Dense(d1, kernel_regularizer=l2(reg_param))(flat1)
        dense = BatchNormalization()(dense)
        dense = Activation("relu")(dense)
        dense = Dense(d2, kernel_regularizer=l2(reg_param))(dense)
        dense = BatchNormalization()(dense)
        dense = Activation("relu")(dense)
        out = Dense(num_outputs, activation=final_activation, kernel_regularizer=l2(reg_param))(
            dense
        )
        model = Model(inputs=inp, outputs=out)
        return model

    def _make_dbitnet(self, input_size=64, n_filters=32, n_add_filters=16):
        """Create a DBITNet model.

        :param input_size: e.g. for SPECK32/64 and 2 ciphertexts, the input_size is 64 bit.
        :return: DBitNet model.
        """

        def get_dilation_rates(input_size):
            """Helper function to determine the dilation rates of DBitNet given an input_size."""
            drs = []
            while input_size >= 8:
                drs.append(int(input_size / 2 - 1))
                input_size = input_size // 2

            return drs

        # determine the dilation rates from the given input size
        dilation_rates = get_dilation_rates(input_size)

        # prediction head parameters (similar to Gohr)
        d1 = 256
        d2 = 64
        reg_param = 1e-5

        # define the input shape
        inputs = Input(shape=(input_size, 1))
        x = inputs

        # normalize the input data to a range of [-1, 1], i.e. (x - 0.5) / 0.5:
        x = Rescaling(scale=2.0, offset=-1.0)(x)

        for dilation_rate in dilation_rates:
            ### wide-narrow blocks
            x = Conv1D(
                filters=n_filters,
                kernel_size=2,
                padding="valid",
                dilation_rate=dilation_rate,
                strides=1,
                activation="relu",
            )(x)
            x = BatchNormalization()(x)
            x_skip = x
            x = Conv1D(
                filters=n_filters,
                kernel_size=2,
                padding="causal",
                dilation_rate=1,
                activation="relu",
            )(x)
            x = Add()([x, x_skip])
            x = BatchNormalization()(x)

            n_filters += n_add_filters

        ### prediction head
        out = tf.keras.layers.Flatten()(x)
        dense0 = Dense(d1, kernel_regularizer=l2(reg_param))(out)
        dense0 = BatchNormalization()(dense0)
        dense0 = Activation("relu")(dense0)
        dense1 = Dense(d1, kernel_regularizer=l2(reg_param))(dense0)
        dense1 = BatchNormalization()(dense1)
        dense1 = Activation("relu")(dense1)
        dense2 = Dense(d2, kernel_regularizer=l2(reg_param))(dense1)
        dense2 = BatchNormalization()(dense2)
        dense2 = Activation("relu")(dense2)
        out = Dense(1, activation="sigmoid", kernel_regularizer=l2(reg_param))(dense2)
        model = Model(inputs, out)
        return model
