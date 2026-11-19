#!/bin/bash
cd "$(dirname "$0")/../../../experimental_results/test_operation_modadd/test_new_chaskey32" || exit 1

MZN=${MZN:-minizinc}
GUROBI_DLL=${GUROBI_DLL:?Set GUROBI_DLL to your Gurobi shared library}

(
    cd ./test_7r_7_1_6/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_2.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_2.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_3.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_3.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_4.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_4.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_5.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_5.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_6.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_6.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_7.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_7.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        chaskey_7r_7_1_6.mzn > test_chaskey_7r_7_1_6_seed_45.log 2>&1
)