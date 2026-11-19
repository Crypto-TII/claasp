#!/bin/bash
cd "$(dirname "$0")/../../../experimental_results/test_operation_modadd/test_new_chaskey32" || exit 1

MZN=${MZN:-minizinc}
GUROBI_DLL=${GUROBI_DLL:?Set GUROBI_DLL to your Gurobi shared library}

(
    cd ./test_5r_5_1_4/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_7.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_7.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        chaskey_5r_5_1_4.mzn > test_chaskey_5r_5_1_4_seed_45.log 2>&1
)