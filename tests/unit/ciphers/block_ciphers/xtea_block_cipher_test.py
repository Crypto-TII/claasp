from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
from claasp.cipher_modules.code_generator import generate_numba_cipher_evaluation_kernel
from numba import cuda, uint8, uint16, uint32, uint64
import numpy as np


def test_xtea_block_cipher():
    xtea = XTeaBlockCipher()
    assert xtea.type == 'block_cipher'
    assert xtea.family_name == 'xtea'
    assert xtea.number_of_rounds == 32
    assert xtea.id == 'xtea_p64_k128_o64_r32'
    assert xtea.component_from(0, 0).id == 'shift_0_0'

    xtea = XTeaBlockCipher(number_of_rounds=4)
    assert xtea.number_of_rounds == 4
    assert xtea.id == 'xtea_p64_k128_o64_r4'
    assert xtea.component_from(3, 0).id == 'shift_3_0'

    xtea = XTeaBlockCipher()
    plaintext = 0xbd7d764dff0ada1e
    key = 0x1de1c3c2c65880074c32dce537b22ab3
    ciphertext = 0x91c0fec24d17fe49
    assert xtea.evaluate([plaintext, key]) == ciphertext
    assert xtea.test_against_reference_code(2) is True
    assert xtea.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    assert xtea.evaluate_vectorized_gpu([plaintext, key], evaluate_api=True) == ciphertext

    xtea = XTeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=32)
    plaintext = 0xb779ee0a
    key = 0x0e2ddd5c5b4ca9d4
    ciphertext = 0x5be9022a
    assert xtea.evaluate([plaintext, key]) == ciphertext
    assert xtea.test_against_reference_code(2) is True
    assert xtea.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    assert xtea.evaluate_vectorized_gpu([plaintext, key], evaluate_api=True) == ciphertext

def test_xtea_numba_matches_evaluate_vectorized_fast():
    xtea = XTeaBlockCipher(number_of_rounds=7)
    pt_hex = '0123456789abcde0'
    key_hex = '000102030405060708090a0b0c0d0e0f'

    pt_n = xtea.inputs_bit_size[xtea.inputs.index('plaintext')] // 8
    key_n = xtea.inputs_bit_size[xtea.inputs.index('key')] // 8

    pt_arr = np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8).reshape(pt_n, 1)
    key_arr = np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8).reshape(key_n, 1)

    input_list = []
    for name in xtea.inputs:
        input_list.append(key_arr if name == 'key' else pt_arr)
    expected = xtea.evaluate_vectorized(input_list)[0][0, :].tobytes().hex()

    _, code = generate_numba_cipher_evaluation_kernel(xtea, mode='differential')
    device_code = code.split('@cuda.jit\ndef differential_kernel')[0]

    eg = {
        'cuda': cuda,
        'uint8': uint8,
        'uint16': uint16,
        'uint32': uint32,
        'uint64': uint64,
        'np': np,
    }
    exec(device_code, eg)
    exec('''@cuda.jit
def test_kernel_xtea_r4(pt, key, out):
    evaluate_cipher(pt, key, out)
''', eg)

    out = np.zeros(pt_n, dtype=np.uint8)
    d_pt = cuda.to_device(np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8).copy())
    d_key = cuda.to_device(np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8).copy())
    d_out = cuda.to_device(out)

    eg['test_kernel_xtea_r4'][1, 1](d_pt, d_key, d_out)
    cuda.synchronize()
    got = d_out.copy_to_host().tobytes().hex()

    print('XTEA rounds=4')
    print(f'  exp: {expected}')
    print(f'  got: {got}')

    assert got == expected



def test_differential_checker_xtea_numba():
    import time
    import math

    from claasp.cipher_modules.models.utils import differential_checker_for_block_cipher_single_key_numba

    input_difference = 0x1234
    fixed_key = 0x00000000000000000000000000000000
    seed = 12

    rounds_data = {
        2: {'out_diff': 0x100000010, 'log2_prob': -41},
    }

    print("\n")
    print("=" * 70)
    print("  XTEA-64/128 - NUMBA Differential Verification")
    print(f"  Input difference: {hex(input_difference)}")
    print("=" * 70)
    print(f"  {'rounds':>6} | {'samples':>8} | {'Numba log2p':>12} | {'theo':>6} | {'time':>8}")
    print("-" * 70)

    for number_of_rounds, data in rounds_data.items():
        xtea = XTeaBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=number_of_rounds)
        block_size = xtea.inputs_bit_size[0]
        key_size = xtea.inputs_bit_size[1]
        output_difference = data['out_diff']

        number_of_samples = 1 << (-data['log2_prob'])
        samples_exp = int(math.log2(number_of_samples))

        start = time.time()
        log2p_numba = differential_checker_for_block_cipher_single_key_numba(
            xtea, input_difference, output_difference,
            number_of_samples, block_size, key_size, fixed_key, seed
        )
        t_numba = time.time() - start

        print(f"  {number_of_rounds:>6} | {'2^'+str(samples_exp):>8} | {log2p_numba:>12.2f} | {data['log2_prob']:>6} | {t_numba:>7.2f}s")

    print("=" * 70)



def test_xtea_numba_batch_efficiency_against_evaluate_vectorized():
    import time
    # Inicializa el cifrado XTEA con 7 rondas
    xtea = LeaBlockCipher(number_of_rounds=7)
    # Tiempo máximo permitido por backend (CPU o GPU)
    timeout_seconds = 30.0
    # Cantidades de samples que se probarán: 2^12, 2^14, ..., 2^20
    sample_exponents = [12, 14, 16, 18, 20]
    # Generador aleatorio reproducible
    rng = np.random.default_rng(12)

    # Número de bytes del plaintext
    pt_n = xtea.inputs_bit_size[xtea.inputs.index('plaintext')] // 8
    # Número de bytes de la key
    key_n = xtea.inputs_bit_size[xtea.inputs.index('key')] // 8

    # Genera código CUDA optimizado para evaluar el cifrado
    _, code = generate_numba_cipher_evaluation_kernel(xtea, mode='differential')

    # Extrae solo la parte necesaria (sin el kernel diferencial)
    device_code = code.split('@cuda.jit\ndef differential_kernel')[0]

    eg = {
        'cuda': cuda,
        'uint8': uint8,
        'uint16': uint16,
        'uint32': uint32,
        'uint64': uint64,
        'np': np,
    }
    # Ejecuta el código generado (define evaluate_cipher en eg)
    exec(device_code, eg)

    #Este es el kernel clave, cada thread toma un plaintext, key y calcula un ciphertext
    batch_kernel_code = """@cuda.jit
def test_kernel_xtea_batch(pt, key, out):
    i = cuda.grid(1)
    if i < pt.shape[1]:
        evaluate_cipher(pt[:, i], key[:, i], out[:, i])
"""
    exec(batch_kernel_code, eg)

    #overhead inicial de compilación JIT
    #mediciones falsas en el primer run
    warm_pt = np.zeros((pt_n, 1), dtype=np.uint8)
    warm_key = np.zeros((key_n, 1), dtype=np.uint8)
    warm_out = np.zeros((pt_n, 1), dtype=np.uint8)
    d_warm_pt = cuda.to_device(warm_pt)
    d_warm_key = cuda.to_device(warm_key)
    d_warm_out = cuda.to_device(warm_out)

    ## Ejecuta una vez para "calentar" la GPU
    eg['test_kernel_xtea_batch'][1, 1](d_warm_pt, d_warm_key, d_warm_out)
    cuda.synchronize()

    print("\n")
    print("=" * 92)
    print("  XTEA-64/128 - Batch Efficiency: evaluate_vectorized vs Numba")
    print(f"  rounds: {xtea.number_of_rounds}")
    print(f"  timeout per backend: {timeout_seconds:.0f}s")
    print("=" * 92)
    print(f"  {'samples':>10} | {'CPU time':>12} | {'Numba time':>12} | {'speedup':>10}")
    print("-" * 92)

    for exp in sample_exponents:
        num_samples = 1 << exp
        #Generación de datos
        pt_arr = rng.integers(0, 256, size=(pt_n, num_samples), dtype=np.uint8)
        key_arr = rng.integers(0, 256, size=(key_n, num_samples), dtype=np.uint8)

        #Evaluación en CPU, calcula TODOS los outputs en CPU y guarda resultado en expected
        input_list = [key_arr if name == 'key' else pt_arr for name in xtea.inputs]

        cpu_status = None
        expected = None
        cpu_start = time.perf_counter()
        expected = xtea.evaluate_vectorized(input_list)[0].T
        cpu_time = time.perf_counter() - cpu_start
        if cpu_time > timeout_seconds:
            cpu_status = 'TIMEOUT'
            expected = None

        #Preparación GPU, Copia datos a GPU 
        out = np.zeros((pt_n, num_samples), dtype=np.uint8)
        d_pt = cuda.to_device(np.ascontiguousarray(pt_arr))
        d_key = cuda.to_device(np.ascontiguousarray(key_arr))
        d_out = cuda.to_device(out)

        #Configuración CUDA
        threads_per_block = 128
        blocks = (num_samples + threads_per_block - 1) // threads_per_block

        #Ejecución GPU, ejecutas el kernel, esperas que termine (synchronize) y traes resultados (got)
        numba_status = None
        numba_start = time.perf_counter()
        eg['test_kernel_xtea_batch'][blocks, threads_per_block](d_pt, d_key, d_out)
        cuda.synchronize()
        got = d_out.copy_to_host()
        numba_time = time.perf_counter() - numba_start
        if numba_time > timeout_seconds:
            numba_status = 'TIMEOUT'

        #Verificación de correctitud, Esto asegura:GPU == CPU exactamente
        if expected is not None:
            assert np.array_equal(got, expected)

        #Cálculo de speedup, speedup=GPU/CPU​
        cpu_display = cpu_status if cpu_status else f'{cpu_time:.4f}s'
        numba_display = numba_status if numba_status else f'{numba_time:.4f}s'
        if cpu_status or numba_status:
            speedup_display = '-'
        else:
            speedup = cpu_time / numba_time if numba_time > 0 else float('inf')
            speedup_display = f'{speedup:.2f}x'

        print(f"  {'2^'+str(exp):>10} | {cpu_display:>12} | {numba_display:>12} | {speedup_display:>10}")

    print("=" * 92)


def test_xtea_numba_gpu_only_large_scale():
    import time

    # Inicializa XTEA
    xtea = XTeaBlockCipher(number_of_rounds=7)

    # Exponentes grandes
    sample_exponents = [22, 25, 30, 35, 38, 40]

    # RNG reproducible
    rng = np.random.default_rng(12)

    # Tamaños
    pt_n = xtea.inputs_bit_size[xtea.inputs.index('plaintext')] // 8
    key_n = xtea.inputs_bit_size[xtea.inputs.index('key')] // 8

    # Generar código CUDA
    _, code = generate_numba_cipher_evaluation_kernel(xtea, mode='differential')
    device_code = code.split('@cuda.jit\ndef differential_kernel')[0]

    eg = {
        'cuda': cuda,
        'uint8': uint8,
        'uint16': uint16,
        'uint32': uint32,
        'uint64': uint64,
        'np': np,
    }

    exec(device_code, eg)

    # Kernel batch (1 thread = 1 cifrado)
    exec("""@cuda.jit
def test_kernel_xtea_batch(pt, key, out):
    i = cuda.grid(1)
    if i < pt.shape[1]:
        evaluate_cipher(pt[:, i], key[:, i], out[:, i])
""", eg)

    # Warm-up GPU
    warm_pt = np.zeros((pt_n, 1), dtype=np.uint8)
    warm_key = np.zeros((key_n, 1), dtype=np.uint8)
    warm_out = np.zeros((pt_n, 1), dtype=np.uint8)

    d_warm_pt = cuda.to_device(warm_pt)
    d_warm_key = cuda.to_device(warm_key)
    d_warm_out = cuda.to_device(warm_out)

    eg['test_kernel_xtea_batch'][1, 1](d_warm_pt, d_warm_key, d_warm_out)
    cuda.synchronize()

    print("\n")
    print("=" * 92)
    print("  XTEA-64/128 - GPU ONLY Large Scale Benchmark")
    print(f"  rounds: {xtea.number_of_rounds}")
    print("=" * 92)
    print(f"  {'samples':>12} | {'GPU time':>12}")
    print("-" * 92)

    for exp in sample_exponents:
        num_samples = 1 << exp

        print(f"\n🔹 Running 2^{exp} samples (~{num_samples:,})")

        # ⚠️ CUIDADO: esto puede explotar memoria
        try:
            pt_arr = rng.integers(0, 256, size=(pt_n, num_samples), dtype=np.uint8)
            key_arr = rng.integers(0, 256, size=(key_n, num_samples), dtype=np.uint8)
            out = np.zeros((pt_n, num_samples), dtype=np.uint8)
        except MemoryError:
            print(f"  2^{exp}: ❌ Not enough RAM")
            continue

        # Copiar a GPU
        try:
            d_pt = cuda.to_device(np.ascontiguousarray(pt_arr))
            d_key = cuda.to_device(np.ascontiguousarray(key_arr))
            d_out = cuda.to_device(out)
        except Exception as e:
            print(f"  2^{exp}: ❌ GPU memory error")
            continue

        # Configuración CUDA
        threads_per_block = 256
        blocks = (num_samples + threads_per_block - 1) // threads_per_block

        # Medir tiempo
        start = time.perf_counter()

        eg['test_kernel_xtea_batch'][blocks, threads_per_block](d_pt, d_key, d_out)
        cuda.synchronize()

        gpu_time = time.perf_counter() - start

        print(f"  {'2^'+str(exp):>12} | {gpu_time:>12.4f}s")

    print("=" * 92)


 
 
def _build_pure_throughput_kernel(cipher):
    from claasp.cipher_modules.code_generator import generate_numba_cipher_evaluation_kernel
 
    _, full_code = generate_numba_cipher_evaluation_kernel(cipher, mode='differential')
    device_code = full_code.split('@cuda.jit\ndef differential_kernel')[0]
 
    pt_n = cipher.inputs_bit_size[cipher.inputs.index('plaintext')] // 8
 
    kernel_code = f"""
@cuda.jit
def throughput_kernel(num_samples, key_bytes, seed, sink):
    idx = cuda.grid(1)
    stride = cuda.gridsize(1)
    pt = cuda.local.array({pt_n}, dtype=uint8)
    ct = cuda.local.array({pt_n}, dtype=uint8)
    for i in range(idx, num_samples, stride):
        s = xorshift64(uint64(i + 1) ^ uint64(seed))
        for b in range({pt_n}):
            pt[b] = uint8((s >> uint64(uint64({pt_n} - 1 - b) * uint64(8))) & uint64(0xFF))
            s = xorshift64(s)
        evaluate_cipher(pt, key_bytes, ct)
        cuda.atomic.add(sink, 0, uint64(ct[0]))
"""
 
    eg = {
        'cuda': cuda, 'uint8': uint8, 'uint16': uint16,
        'uint32': uint32, 'uint64': uint64, 'np': np,
    }
    exec(device_code, eg)
    exec(kernel_code, eg)
    return eg['throughput_kernel']
 
 
def test_xtea_pure_throughput():
    import time
 
    number_of_rounds = 7
    xtea = XTeaBlockCipher(number_of_rounds=number_of_rounds)
 
    key_size = xtea.inputs_bit_size[xtea.inputs.index('key')]
    key_n    = key_size // 8
    fixed_key = 0x0
    key_bytes = np.array(
        [(fixed_key >> (8 * (key_n - 1 - i))) & 0xFF for i in range(key_n)],
        dtype=np.uint8
    )
    seed = 42
 
    print("\nCompilando kernel...")
    t0 = time.perf_counter()
    kernel = _build_pure_throughput_kernel(xtea)
    print(f"  codegen: {time.perf_counter() - t0:.3f}s")
 
    d_key  = cuda.to_device(key_bytes)
    d_sink = cuda.to_device(np.array([0], dtype=np.uint64))
 
    print("Warm-up (JIT)...")
    t0 = time.perf_counter()
    kernel[1, 256](uint64(256), d_key, uint64(seed), d_sink)
    cuda.synchronize()
    print(f"  warmup: {time.perf_counter() - t0:.3f}s")
 
    sample_exponents  = [20, 24, 28, 30, 32, 34]
    threads_per_block = 256
    max_blocks        = 4096
 
    print()
    print("=" * 65)
    print(f"  XTEA-64/128 — Pure throughput  (rounds={number_of_rounds})")
    print(f"  VRAM: {key_n} bytes (key) + 8 bytes (sink) — O(1)")
    print("=" * 65)
    print(f"  {'samples':>10} | {'threads':>11} | {'time':>9} | {'Mevals/s':>10} | {'Gevals/s':>9}")
    print("-" * 65)
 
    for exp in sample_exponents:
        num_samples = 1 << exp
        blocks      = min(max_blocks, (num_samples + threads_per_block - 1) // threads_per_block)
        num_threads = blocks * threads_per_block
 
        d_sink.copy_to_device(np.array([0], dtype=np.uint64))
 
        t0 = time.perf_counter()
        kernel[blocks, threads_per_block](uint64(num_samples), d_key, uint64(seed), d_sink)
        cuda.synchronize()
        elapsed = time.perf_counter() - t0
 
        mevals = (num_samples / elapsed) / 1e6
        gevals = (num_samples / elapsed) / 1e9
 
        print(f"  {'2^'+str(exp):>10} | {num_threads:>11,} | {elapsed:>8.3f}s | {mevals:>9.1f}M | {gevals:>8.3f}G")
 
    print("=" * 65)
    print()
    print("Nota: sink acumula ct[0] de cada evaluacion para evitar")
    print("que el compilador CUDA elimine evaluate_cipher como dead code.")