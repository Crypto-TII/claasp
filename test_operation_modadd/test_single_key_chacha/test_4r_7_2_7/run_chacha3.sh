#!/bin/bash
cd "$(dirname "$0")" || exit 1

MZN=/opt/MiniZincIDE-2.9.5-bundle-linux-x86_64/bin/minizinc
GUROBI_DLL=/opt/gurobi1302/linux64/lib/libgurobi.so.13.0.2

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_5.prm \
    --verbose --statistics \
    chacha_4r_7_2_7.mzn > test_chacha_4r_7_2_7_seed_5.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_6.prm \
    --verbose --statistics \
    chacha_4r_7_2_7.mzn > test_chacha_4r_7_2_7_seed_6.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_7.prm \
    --verbose --statistics \
    chacha_4r_7_2_7.mzn > test_chacha_4r_7_2_7_seed_7.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_8.prm \
    --verbose --statistics \
    chacha_4r_7_2_7.mzn > test_chacha_4r_7_2_7_seed_8.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_45.prm \
    --verbose --statistics \
    chacha_4r_7_2_7.mzn > test_chacha_4r_7_2_7_seed_45.log 2>&1

(
    cd ../test_4r_8_1_7/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_0.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_0.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_1.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_1.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_2.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_2.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_3.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_3.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_4.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_4.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_5.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_5.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_6.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_6.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_7.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_7.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_8.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_8.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_45.prm \
        --verbose --statistics \
        chacha_4r_8_1_7.mzn > test_chacha_4r_8_1_7_seed_45.log 2>&1
)