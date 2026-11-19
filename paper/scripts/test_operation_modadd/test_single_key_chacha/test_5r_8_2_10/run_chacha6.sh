cd "$(dirname "$0")/../../../../experimental_results/test_operation_modadd/test_single_key_chacha/test_5r_8_2_10" || exit 1

MZN=${MZN:-minizinc}
GUROBI_DLL=${GUROBI_DLL:?Set GUROBI_DLL to your Gurobi shared library}

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_0.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_0.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_1.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_1.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_2.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_2.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_3.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_3.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_4.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_4.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_5.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_5.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_6.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_6.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_7.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_7.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_8.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_8.log 2>&1

$MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
    --readParam ../../gurobi_params_suggested_45.prm \
    --verbose --statistics \
    chacha_5r_8_2_10.mzn > test_chacha_5r_8_2_10_seed_45.log 2>&1

(
    cd ../test_5r_9_2_9/ || exit 1
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_0.prm \
        --verbose --statistics \
        chacha_5r_9_2_9.mzn > test_chacha_5r_9_2_9_seed_0.log 2>&1
        
    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_1.prm \
        --verbose --statistics \
        chacha_5r_9_2_9.mzn > test_chacha_5r_9_2_9_seed_1.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_2.prm \
        --verbose --statistics \
        chacha_5r_9_2_9.mzn > test_chacha_5r_9_2_9_seed_2.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_3.prm \
        --verbose --statistics \
        chacha_5r_9_2_9.mzn > test_chacha_5r_9_2_9_seed_3.log 2>&1

    $MZN --solver gurobi --gurobi-dll $GUROBI_DLL \
        --readParam ../../gurobi_params_suggested_4.prm \
        --verbose --statistics \
        chacha_5r_9_2_9.mzn > test_chacha_5r_9_2_9_seed_4.log 2>&1
)