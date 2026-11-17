#!/bin/bash
cd "$(dirname "$0")" || exit 1

MZN=/opt/MiniZincIDE-2.9.5-bundle-linux-x86_64/bin/minizinc
GUROBI_DLL=/opt/gurobi1302/linux64/lib/libgurobi.so.13.0.2

(
    cd ./test_5r_4_3_3/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        chaskey_5r_4_3_3.mzn > test_chaskey_5r_4_3_3_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        chaskey_5r_4_3_3.mzn > test_chaskey_5r_4_3_3_seed_45.log 2>&1
)

(
    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_0.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_0.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_1.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_1.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_2.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_2.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_3.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_3.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_4.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_4.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_5.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_5.log 2>&1
)