#!/bin/bash
cd "$(dirname "$0")" || exit 1

MZN=/opt/MiniZincIDE-2.9.5-bundle-linux-x86_64/bin/minizinc
GUROBI_DLL=/opt/gurobi1302/linux64/lib/libgurobi.so.13.0.2

(
    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_6.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_6.log 2>&1

    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_7.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_7.log 2>&1

    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_8.log 2>&1

    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_45.log 2>&1
)

(
    cd ./test_6r_5_2_5/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_0.prm \
        --verbose --statistics \
        chaskey_6r_5_2_5.mzn > test_chaskey_6r_5_2_5_seed_0.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_1.prm \
        --verbose --statistics \
        chaskey_6r_5_2_5.mzn > test_chaskey_6r_5_2_5_seed_1.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_2.prm \
        --verbose --statistics \
        chaskey_6r_5_2_5.mzn > test_chaskey_6r_5_2_5_seed_2.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_3.prm \
        --verbose --statistics \
        chaskey_6r_5_2_5.mzn > test_chaskey_6r_5_2_5_seed_3.log 2>&1
)