#!/bin/bash
cd "$(dirname "$0")/../../../experimental_results/test_operation_modadd/test_new_lea" || exit 1

MZN=${MZN:-minizinc}
GUROBI_DLL=${GUROBI_DLL:?Set GUROBI_DLL to your Gurobi shared library}

(
    cd ./test_15r_7_1_7/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        lea_15r_7_1_7.mzn > test_lea_15r_7_1_7_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        lea_15r_7_1_7.mzn > test_lea_15r_7_1_7_seed_45.log 2>&1
)

(
    cd ./test_16r_8_1_7/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        lea_16r_8_1_7.mzn > test_lea_16r_8_1_7_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        lea_16r_8_1_7.mzn > test_lea_16r_8_1_7_seed_45.log 2>&1
)