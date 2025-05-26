# Neural Detonator

### Description:
A standalone machine learning file surfaced on Volnaya’s firmware staging server. No docs. No entrypoint. No task. Just quiet intent. It’s waiting for something. So are we.

### Objective:
* Inspect the model architecture, decode suspicious Lambda logic, and discover any embedded behavior.
* Reconstruct the XOR key derived from model weights.
* Use it to decrypt the embedded payload and recover the flag.

### Difficulty:
* `Hard`

### Challenge:
You’re provided with a `.keras` file named `mlcious.keras`. This challenge is entirely black-box: no starting code, no input/output hints — just a seemingly valid Keras model. Your mission is to reverse-engineer it and see what it hides.

**File:**
- `mlcious.keras`

---

### Solver:

#### Step 1: Load and Inspect the Model

We start by unpacking the `.keras` archive to see what's inside:

```bash
unzip mlcious.keras
```

Contents:
```
metadata.json
config.json
model.weights.h5
```

Next, we dump the layer names to identify potential leads:

```python
from tensorflow import keras
model = keras.models.load_model("mlcious.keras", safe_mode=False, compile=False)

for l in model.layers:
    print(l.name, l.__class__.__name__)
```

Output:
```
input_layer_1 InputLayer
conv2d_15 Conv2D
batch_normalization_12 BatchNormalization
re_lu_12 ReLU
conv2d_16 Conv2D
conv2d_17 Conv2D
batch_normalization_13 BatchNormalization
add_6 Add
re_lu_13 ReLU
conv2d_18 Conv2D
batch_normalization_14 BatchNormalization
re_lu_14 ReLU
conv2d_19 Conv2D
batch_normalization_15 BatchNormalization
add_7 Add
re_lu_15 ReLU
conv2d_20 Conv2D
batch_normalization_16 BatchNormalization
re_lu_16 ReLU
conv2d_21 Conv2D
conv2d_22 Conv2D
batch_normalization_17 BatchNormalization
add_8 Add
re_lu_17 ReLU
conv2d_23 Conv2D
batch_normalization_18 BatchNormalization
re_lu_18 ReLU
conv2d_24 Conv2D
batch_normalization_19 BatchNormalization
add_9 Add
re_lu_19 ReLU
conv2d_25 Conv2D
batch_normalization_20 BatchNormalization
re_lu_20 ReLU
conv2d_26 Conv2D
conv2d_27 Conv2D
batch_normalization_21 BatchNormalization
add_10 Add
re_lu_21 ReLU
conv2d_28 Conv2D
batch_normalization_22 BatchNormalization
re_lu_22 ReLU
conv2d_29 Conv2D
batch_normalization_23 BatchNormalization
add_11 Add
re_lu_23 ReLU
global_average_pooling2d_1 GlobalAveragePooling2D
seed_dense Dense
payload_dense Dense
dense_1 Dense
activation_adapter Lambda
```

Suspicious layers found at the end:
```
payload_dense Dense and activation_adapter Lambda 
```

---

#### Step 2: Dump and Decode the activation_adapter Lambda

Inside `config.json`, the Lambda layer encodes its logic using base64 + `marshal`:

```json
"function": ["YwAAAAAA...truncated...", null, null]
```

We decode it like so:

```python
import base64, marshal, dis

encoded = "YwAAAA..."  # truncated
raw = base64.b64decode(encoded)
code = marshal.loads(raw)

dis.dis(code)
dis.show_code(code)
```
Output:

```
  0           0 RESUME                   0

  2           2 LOAD_CONST               0 (0)
              4 LOAD_CONST               1 (None)
              6 IMPORT_NAME              0 (marshal)
              8 STORE_NAME               0 (marshal)
             10 LOAD_CONST               0 (0)
             12 LOAD_CONST               1 (None)
             14 IMPORT_NAME              1 (tensorflow)
             16 STORE_NAME               2 (tf)
             18 LOAD_CONST               0 (0)
             20 LOAD_CONST               1 (None)
             22 IMPORT_NAME              3 (random)
             24 STORE_NAME               3 (random)
             26 LOAD_CONST               0 (0)
             28 LOAD_CONST               1 (None)
             30 IMPORT_NAME              4 (struct)
             32 STORE_NAME               4 (struct)
             34 LOAD_CONST               0 (0)
             36 LOAD_CONST               1 (None)
             38 IMPORT_NAME              5 (hashlib)
             40 STORE_NAME               5 (hashlib)

  4          42 LOAD_CONST               2 (<code object trampoline at 0x370832c0, file "<trampoline>", line 4>)
             44 MAKE_FUNCTION            0
             46 STORE_NAME               6 (trampoline)
             48 LOAD_CONST               1 (None)
             50 RETURN_VALUE

Disassembly of <code object trampoline at 0x370832c0, file "<trampoline>", line 4>:
              0 MAKE_CELL                9 (key)

  4           2 RESUME                   0

  5           4 LOAD_CONST               1 (<code object <listcomp> at 0x7f42fd54b9f0, file "<trampoline>", line 5>)
              6 MAKE_FUNCTION            0
              8 LOAD_GLOBAL              0 (tf)
             20 LOAD_ATTR                1 (compat)
             30 LOAD_ATTR                2 (v1)
             40 LOAD_METHOD              3 (global_variables)
             62 PRECALL                  0
             66 CALL                     0
             76 GET_ITER
             78 PRECALL                  0
             82 CALL                     0
             92 LOAD_CONST               2 (0)
             94 BINARY_SUBSCR
            104 STORE_FAST               2 (v1)

  6         106 LOAD_CONST               3 (<code object <listcomp> at 0x7f42fd54bc90, file "<trampoline>", line 6>)
            108 MAKE_FUNCTION            0
            110 LOAD_GLOBAL              0 (tf)
            122 LOAD_ATTR                1 (compat)
            132 LOAD_ATTR                2 (v1)
            142 LOAD_METHOD              3 (global_variables)
            164 PRECALL                  0
            168 CALL                     0
            178 GET_ITER
            180 PRECALL                  0
            184 CALL                     0
            194 LOAD_CONST               2 (0)
            196 BINARY_SUBSCR
            206 STORE_FAST               3 (v2)

  7         208 LOAD_GLOBAL              0 (tf)
            220 LOAD_ATTR                4 (keras)
            230 LOAD_ATTR                5 (backend)
            240 LOAD_METHOD              6 (get_value)
            262 LOAD_FAST                2 (v1)
            264 PRECALL                  1
            268 CALL                     1
            278 STORE_FAST               4 (d1)

  8         280 LOAD_GLOBAL              0 (tf)
            292 LOAD_ATTR                4 (keras)
            302 LOAD_ATTR                5 (backend)
            312 LOAD_METHOD              6 (get_value)
            334 LOAD_FAST                3 (v2)
            336 PRECALL                  1
            340 CALL                     1
            350 STORE_FAST               5 (d2)

  9         352 LOAD_GLOBAL             15 (NULL + struct)
            364 LOAD_ATTR                8 (unpack)
            374 LOAD_CONST               4 ('<I')
            376 LOAD_GLOBAL             19 (NULL + hashlib)
            388 LOAD_ATTR               10 (sha1)
            398 LOAD_FAST                4 (d1)
            400 LOAD_METHOD             11 (tobytes)
            422 PRECALL                  0
            426 CALL                     0
            436 LOAD_FAST                5 (d2)
            438 LOAD_METHOD             11 (tobytes)
            460 PRECALL                  0
            464 CALL                     0
            474 BINARY_OP                0 (+)
            478 PRECALL                  1
            482 CALL                     1
            492 LOAD_METHOD             12 (digest)
            514 PRECALL                  0
            518 CALL                     0
            528 LOAD_CONST               0 (None)
            530 LOAD_CONST               5 (4)
            532 BUILD_SLICE              2
            534 BINARY_SUBSCR
            544 PRECALL                  2
            548 CALL                     2
            558 LOAD_CONST               2 (0)
            560 BINARY_SUBSCR
            570 STORE_FAST               6 (seed)

 10         572 LOAD_GLOBAL             27 (NULL + random)
            584 LOAD_ATTR               14 (Random)
            594 LOAD_FAST                6 (seed)
            596 PRECALL                  1
            600 CALL                     1
            610 LOAD_METHOD             15 (randbytes)
            632 LOAD_CONST               6 (32)
            634 PRECALL                  1
            638 CALL                     1
            648 STORE_DEREF              9 (key)

 11         650 LOAD_GLOBAL             33 (NULL + bytes)
            662 LOAD_CLOSURE             9 (key)
            664 BUILD_TUPLE              1
            666 LOAD_CONST               7 (<code object <genexpr> at 0x7f439a51c130, file "<trampoline>", line 11>)
            668 MAKE_FUNCTION            8 (closure)
            670 LOAD_GLOBAL             35 (NULL + enumerate)
            682 BUILD_LIST               0
            684 LOAD_CONST               8 ((171, 201, 49, ... , 127, 82, 102))
            686 LIST_EXTEND              1
            688 PRECALL                  1
            692 CALL                     1
            702 GET_ITER
            704 PRECALL                  0
            708 CALL                     0
            718 PRECALL                  1
            722 CALL                     1
            732 STORE_FAST               7 (code)

 12         734 BUILD_MAP                0
            736 STORE_FAST               8 (ns)
            738 LOAD_GLOBAL             37 (NULL + exec)
            750 LOAD_GLOBAL             39 (NULL + marshal)
            762 LOAD_ATTR               20 (loads)
            772 LOAD_FAST                7 (code)
            774 PRECALL                  1
            778 CALL                     1
            788 LOAD_FAST                8 (ns)
            790 PRECALL                  2
            794 CALL                     2
            804 POP_TOP

 13         806 PUSH_NULL
            808 LOAD_FAST                8 (ns)
            810 LOAD_CONST               9 ('payload')
            812 BINARY_SUBSCR
            822 LOAD_FAST                0 (x)
            824 LOAD_FAST                1 (_)
            826 PRECALL                  2
            830 CALL                     2
            840 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f42fd54b9f0, file "<trampoline>", line 5>:
  5           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/kernel')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f42fd54bc90, file "<trampoline>", line 6>:
  6           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/bias')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <genexpr> at 0x7f439a51c130, file "<trampoline>", line 11>:
              0 COPY_FREE_VARS           1

 11           2 RETURN_GENERATOR
              4 POP_TOP
              6 RESUME                   0
              8 LOAD_FAST                0 (.0)
        >>   10 FOR_ITER                21 (to 54)
             12 UNPACK_SEQUENCE          2
             16 STORE_FAST               1 (i)
             18 STORE_FAST               2 (c)
             20 LOAD_FAST                2 (c)
             22 LOAD_DEREF               3 (key)
             24 LOAD_FAST                1 (i)
             26 LOAD_CONST               0 (32)
             28 BINARY_OP                6 (%)
             32 BINARY_SUBSCR
             42 BINARY_OP               12 (^)
             46 YIELD_VALUE
             48 RESUME                   1
             50 POP_TOP
             52 JUMP_BACKWARD           22 (to 10)
        >>   54 LOAD_CONST               1 (None)
             56 RETURN_VALUE

```
This reveals a function that imports `marshal`, `random`, `tensorflow`, `struct`, and `hashlib`. It then defines a nested function called `trampoline`.

We observe the pattern:

- Pull two specific tensors (`seed_dense/kernel` and `seed_dense/bias`)
- Use SHA-1 on their `.tobytes()` to derive a seed
- Feed that seed into Python’s `random.Random(seed).randbytes(32)`
- XOR that 32-byte key against an embedded payload.

But the actual malicious logic is still encrypted!

---

#### Step 3: Dissecting the Trampoline Lambda

We disassemble the inner trampoline function:

```python
dis.dis(code.co_consts[2])  # trampoline code object
```
Output:
```
              0 MAKE_CELL                9 (key)

  4           2 RESUME                   0

  5           4 LOAD_CONST               1 (<code object <listcomp> at 0x7a21c0cd56f0, file "<trampoline>", line 5>)
              6 MAKE_FUNCTION            0
              8 LOAD_GLOBAL              0 (tf)
             20 LOAD_ATTR                1 (compat)
             30 LOAD_ATTR                2 (v1)
             40 LOAD_METHOD              3 (global_variables)
             62 PRECALL                  0
             66 CALL                     0
             76 GET_ITER
             78 PRECALL                  0
             82 CALL                     0
             92 LOAD_CONST               2 (0)
             94 BINARY_SUBSCR
            104 STORE_FAST               2 (v1)

  6         106 LOAD_CONST               3 (<code object <listcomp> at 0x7a211656c110, file "<trampoline>", line 6>)
            108 MAKE_FUNCTION            0
            110 LOAD_GLOBAL              0 (tf)
            122 LOAD_ATTR                1 (compat)
            132 LOAD_ATTR                2 (v1)
            142 LOAD_METHOD              3 (global_variables)
            164 PRECALL                  0
            168 CALL                     0
            178 GET_ITER
            180 PRECALL                  0
            184 CALL                     0
            194 LOAD_CONST               2 (0)
            196 BINARY_SUBSCR
            206 STORE_FAST               3 (v2)

  7         208 LOAD_GLOBAL              0 (tf)
            220 LOAD_ATTR                4 (keras)
            230 LOAD_ATTR                5 (backend)
            240 LOAD_METHOD              6 (get_value)
            262 LOAD_FAST                2 (v1)
            264 PRECALL                  1
            268 CALL                     1
            278 STORE_FAST               4 (d1)

  8         280 LOAD_GLOBAL              0 (tf)
            292 LOAD_ATTR                4 (keras)
            302 LOAD_ATTR                5 (backend)
            312 LOAD_METHOD              6 (get_value)
            334 LOAD_FAST                3 (v2)
            336 PRECALL                  1
            340 CALL                     1
            350 STORE_FAST               5 (d2)

  9         352 LOAD_GLOBAL             15 (NULL + struct)
            364 LOAD_ATTR                8 (unpack)
            374 LOAD_CONST               4 ('<I')
            376 LOAD_GLOBAL             19 (NULL + hashlib)
            388 LOAD_ATTR               10 (sha1)
            398 LOAD_FAST                4 (d1)
            400 LOAD_METHOD             11 (tobytes)
            422 PRECALL                  0
            426 CALL                     0
            436 LOAD_FAST                5 (d2)
            438 LOAD_METHOD             11 (tobytes)
            460 PRECALL                  0
            464 CALL                     0
            474 BINARY_OP                0 (+)
            478 PRECALL                  1
            482 CALL                     1
            492 LOAD_METHOD             12 (digest)
            514 PRECALL                  0
            518 CALL                     0
            528 LOAD_CONST               0 (None)
            530 LOAD_CONST               5 (4)
            532 BUILD_SLICE              2
            534 BINARY_SUBSCR
            544 PRECALL                  2
            548 CALL                     2
            558 LOAD_CONST               2 (0)
            560 BINARY_SUBSCR
            570 STORE_FAST               6 (seed)

 10         572 LOAD_GLOBAL             27 (NULL + random)
            584 LOAD_ATTR               14 (Random)
            594 LOAD_FAST                6 (seed)
            596 PRECALL                  1
            600 CALL                     1
            610 LOAD_METHOD             15 (randbytes)
            632 LOAD_CONST               6 (32)
            634 PRECALL                  1
            638 CALL                     1
            648 STORE_DEREF              9 (key)

 11         650 LOAD_GLOBAL             33 (NULL + bytes)
            662 LOAD_CLOSURE             9 (key)
            664 BUILD_TUPLE              1
            666 LOAD_CONST               7 (<code object <genexpr> at 0x7a214d4d6730, file "<trampoline>", line 11>)
            668 MAKE_FUNCTION            8 (closure)
            670 LOAD_GLOBAL             35 (NULL + enumerate)
            682 BUILD_LIST               0
            684 LOAD_CONST               8 ((171, 201, 49, ... , 82, 102))
            686 LIST_EXTEND              1
            688 PRECALL                  1
            692 CALL                     1
            702 GET_ITER
            704 PRECALL                  0
            708 CALL                     0
            718 PRECALL                  1
            722 CALL                     1
            732 STORE_FAST               7 (code)

 12         734 BUILD_MAP                0
            736 STORE_FAST               8 (ns)
            738 LOAD_GLOBAL             37 (NULL + exec)
            750 LOAD_GLOBAL             39 (NULL + marshal)
            762 LOAD_ATTR               20 (loads)
            772 LOAD_FAST                7 (code)
            774 PRECALL                  1
            778 CALL                     1
            788 LOAD_FAST                8 (ns)
            790 PRECALL                  2
            794 CALL                     2
            804 POP_TOP

 13         806 PUSH_NULL
            808 LOAD_FAST                8 (ns)
            810 LOAD_CONST               9 ('payload')
            812 BINARY_SUBSCR
            822 LOAD_FAST                0 (x)
            824 LOAD_FAST                1 (_)
            826 PRECALL                  2
            830 CALL                     2
            840 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7a21c0cd56f0, file "<trampoline>", line 5>:
  5           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/kernel')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7a211656c110, file "<trampoline>", line 6>:
  6           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/bias')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <genexpr> at 0x7a214d4d6730, file "<trampoline>", line 11>:
              0 COPY_FREE_VARS           1

 11           2 RETURN_GENERATOR
              4 POP_TOP
              6 RESUME                   0
              8 LOAD_FAST                0 (.0)
        >>   10 FOR_ITER                21 (to 54)
             12 UNPACK_SEQUENCE          2
             16 STORE_FAST               1 (i)
             18 STORE_FAST               2 (c)
             20 LOAD_FAST                2 (c)
             22 LOAD_DEREF               3 (key)
             24 LOAD_FAST                1 (i)
             26 LOAD_CONST               0 (32)
             28 BINARY_OP                6 (%)
             32 BINARY_SUBSCR
             42 BINARY_OP               12 (^)
             46 YIELD_VALUE
             48 RESUME                   1
             50 POP_TOP
             52 JUMP_BACKWARD           22 (to 10)
        >>   54 LOAD_CONST               1 (None)
             56 RETURN_VALUE
```
It contains this logic:
- Locate `seed_dense/kernel` and `seed_dense/bias`
- Call `tf.keras.backend.get_value(...)` to retrieve raw tensors
- Generate a seed:
  ```python
  seed = struct.unpack("<I", sha1(d1 + d2).digest()[:4])[0]
  ```
- Generate key:
  ```python
  key = random.Random(seed).randbytes(32)
  ```

Then:
- XOR a hardcoded list of integers (the encrypted blob) against that key
- Pass the result to `marshal.loads(...)`
- Execute it in a new namespace

This is a trampoline — it decrypts and executes a second payload at runtime.

---

#### Step 4: Derive the Key

We manually extract weights and follow the exact seed derivation:

```python
import struct, hashlib, random

w1, b1 = model.get_layer("seed_dense").get_weights()
digest = hashlib.sha1(w1.tobytes() + b1.tobytes()).digest()
seed = struct.unpack("<I", digest[:4])[0]
print(hex(seed))
key = list(random.Random(seed).randbytes(32))
print("Key:", key)
```

Result:
```
Derived seed: 0x39814100
Key: [200, 201, 49, 173, 77, 143, 42, 194, 45, 213, 147, 223, 68, 44, 144, 65, 251, 2, 229, 70, 88, 180, 101, 86, 190, 243, 127, 82, 102, 120, 86, 149]
```

---

#### Step 5: Decrypt and Unmarshal Payload

We find the encrypted blob in the trampoline disassembly:

```python
enc = [171, 201, 49, 173, 77, 143, 42, 194, 45, 213, 147, 223, 68, 46, 144, 65, 251, 2, ... , 82, 102]
```

We XOR it with the derived key and decode the result:

```python
payload_code = bytes(c ^ key[i % 32] for i, c in enumerate(enc))
payload_func = marshal.loads(payload_code)
dis.dis(payload_func)
```

Now we finally reveal the logic of the hidden payload.

```

  0           0 RESUME                   0

  2           2 LOAD_CONST               0 (0)
              4 LOAD_CONST               1 (None)
              6 IMPORT_NAME              0 (tensorflow)
              8 STORE_NAME               1 (tf)
             10 LOAD_CONST               0 (0)
             12 LOAD_CONST               1 (None)
             14 IMPORT_NAME              2 (base64)
             16 STORE_NAME               2 (base64)

  4          18 LOAD_CONST               2 (<code object payload at 0x370a0fd0, file "<payload>", line 4>)
             20 MAKE_FUNCTION            0
             22 STORE_NAME               3 (payload)
             24 LOAD_CONST               1 (None)
             26 RETURN_VALUE

Disassembly of <code object payload at 0x370a0fd0, file "<payload>", line 4>:
              0 MAKE_CELL               13 (key)

  4           2 RESUME                   0

  5           4 LOAD_GLOBAL              0 (tf)
             16 LOAD_ATTR                1 (keras)
             26 LOAD_ATTR                2 (backend)
             36 LOAD_METHOD              3 (get_value)

  6          58 LOAD_CONST               1 (<code object <listcomp> at 0x7f42fd54bd70, file "<payload>", line 6>)
             60 MAKE_FUNCTION            0
             62 LOAD_GLOBAL              0 (tf)
             74 LOAD_ATTR                4 (compat)
             84 LOAD_ATTR                5 (v1)
             94 LOAD_METHOD              6 (global_variables)
            116 PRECALL                  0
            120 CALL                     0
            130 GET_ITER
            132 PRECALL                  0
            136 CALL                     0
            146 LOAD_CONST               2 (0)
            148 BINARY_SUBSCR

  5         158 PRECALL                  1
            162 CALL                     1
            172 STORE_FAST               2 (bias)

  7         174 LOAD_GLOBAL              1 (NULL + tf)
            186 LOAD_ATTR                7 (cast)
            196 LOAD_FAST                2 (bias)
            198 LOAD_CONST               0 (None)
            200 LOAD_CONST               3 (22)
            202 BUILD_SLICE              2
            204 BINARY_SUBSCR
            214 LOAD_CONST               4 (255.0)
            216 BINARY_OP                5 (*)
            220 LOAD_GLOBAL              0 (tf)
            232 LOAD_ATTR                8 (uint8)
            242 PRECALL                  2
            246 CALL                     2
            256 LOAD_METHOD              9 (numpy)
            278 PRECALL                  0
            282 CALL                     0
            292 LOAD_METHOD             10 (tobytes)
            314 PRECALL                  0
            318 CALL                     0
            328 STORE_FAST               3 (enc)

  8         330 LOAD_CONST               5 (<code object <listcomp> at 0x7f42fc882f70, file "<payload>", line 8>)
            332 MAKE_FUNCTION            0
            334 LOAD_GLOBAL              0 (tf)
            346 LOAD_ATTR                4 (compat)
            356 LOAD_ATTR                5 (v1)
            366 LOAD_METHOD              6 (global_variables)
            388 PRECALL                  0
            392 CALL                     0
            402 GET_ITER
            404 PRECALL                  0
            408 CALL                     0
            418 LOAD_CONST               2 (0)
            420 BINARY_SUBSCR
            430 STORE_FAST               4 (v1)

  9         432 LOAD_CONST               6 (<code object <listcomp> at 0x7f42fc8834b0, file "<payload>", line 9>)
            434 MAKE_FUNCTION            0
            436 LOAD_GLOBAL              0 (tf)
            448 LOAD_ATTR                4 (compat)
            458 LOAD_ATTR                5 (v1)
            468 LOAD_METHOD              6 (global_variables)
            490 PRECALL                  0
            494 CALL                     0
            504 GET_ITER
            506 PRECALL                  0
            510 CALL                     0
            520 LOAD_CONST               2 (0)
            522 BINARY_SUBSCR
            532 STORE_FAST               5 (v2)

 10         534 LOAD_GLOBAL              0 (tf)
            546 LOAD_ATTR                1 (keras)
            556 LOAD_ATTR                2 (backend)
            566 LOAD_METHOD              3 (get_value)
            588 LOAD_FAST                4 (v1)
            590 PRECALL                  1
            594 CALL                     1
            604 STORE_FAST               6 (d1)

 11         606 LOAD_GLOBAL              0 (tf)
            618 LOAD_ATTR                1 (keras)
            628 LOAD_ATTR                2 (backend)
            638 LOAD_METHOD              3 (get_value)
            660 LOAD_FAST                5 (v2)
            662 PRECALL                  1
            666 CALL                     1
            676 STORE_FAST               7 (d2)

 12         678 LOAD_CONST               2 (0)
            680 LOAD_CONST               0 (None)
            682 IMPORT_NAME             11 (hashlib)
            684 STORE_FAST               8 (hashlib)
            686 LOAD_CONST               2 (0)
            688 LOAD_CONST               0 (None)
            690 IMPORT_NAME             12 (struct)
            692 STORE_FAST               9 (struct)
            694 LOAD_CONST               2 (0)
            696 LOAD_CONST               0 (None)
            698 IMPORT_NAME             13 (random)
            700 STORE_FAST              10 (random)

 13         702 LOAD_FAST                9 (struct)
            704 LOAD_METHOD             14 (unpack)
            726 LOAD_CONST               7 ('<I')
            728 LOAD_FAST                8 (hashlib)
            730 LOAD_METHOD             15 (sha1)
            752 LOAD_FAST                6 (d1)
            754 LOAD_METHOD             10 (tobytes)
            776 PRECALL                  0
            780 CALL                     0
            790 LOAD_FAST                7 (d2)
            792 LOAD_METHOD             10 (tobytes)
            814 PRECALL                  0
            818 CALL                     0
            828 BINARY_OP                0 (+)
            832 PRECALL                  1
            836 CALL                     1
            846 LOAD_METHOD             16 (digest)
            868 PRECALL                  0
            872 CALL                     0
            882 LOAD_CONST               0 (None)
            884 LOAD_CONST               8 (4)
            886 BUILD_SLICE              2
            888 BINARY_SUBSCR
            898 PRECALL                  2
            902 CALL                     2
            912 LOAD_CONST               2 (0)
            914 BINARY_SUBSCR
            924 STORE_FAST              11 (seed)

 14         926 LOAD_FAST               10 (random)
            928 LOAD_METHOD             17 (Random)
            950 LOAD_FAST               11 (seed)
            952 PRECALL                  1
            956 CALL                     1
            966 LOAD_METHOD             18 (randbytes)
            988 LOAD_CONST               9 (32)
            990 PRECALL                  1
            994 CALL                     1
           1004 STORE_DEREF             13 (key)

 15        1006 LOAD_GLOBAL             39 (NULL + bytes)
           1018 LOAD_CLOSURE            13 (key)
           1020 BUILD_TUPLE              1
           1022 LOAD_CONST              10 (<code object <genexpr> at 0x7f43009ae830, file "<payload>", line 15>)
           1024 MAKE_FUNCTION            8 (closure)
           1026 LOAD_GLOBAL             41 (NULL + enumerate)
           1038 LOAD_FAST                3 (enc)
           1040 PRECALL                  1
           1044 CALL                     1
           1054 GET_ITER
           1056 PRECALL                  0
           1060 CALL                     0
           1070 PRECALL                  1
           1074 CALL                     1
           1084 STORE_FAST              12 (flag)

 16        1086 LOAD_FAST                0 (x)
           1088 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f42fd54bd70, file "<payload>", line 6>:
  6           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('payload_dense/bias')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f42fc882f70, file "<payload>", line 8>:
  8           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/kernel')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f42fc8834b0, file "<payload>", line 9>:
  9           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                13 (to 34)
              8 STORE_FAST               1 (v)
             10 LOAD_CONST               0 ('seed_dense/bias')
             12 LOAD_FAST                1 (v)
             14 LOAD_ATTR                0 (name)
             24 CONTAINS_OP              0
             26 POP_JUMP_BACKWARD_IF_FALSE    11 (to 6)
             28 LOAD_FAST                1 (v)
             30 LIST_APPEND              2
             32 JUMP_BACKWARD           14 (to 6)
        >>   34 RETURN_VALUE

Disassembly of <code object <genexpr> at 0x7f43009ae830, file "<payload>", line 15>:
              0 COPY_FREE_VARS           1

 15           2 RETURN_GENERATOR
              4 POP_TOP
              6 RESUME                   0
              8 LOAD_FAST                0 (.0)
        >>   10 FOR_ITER                21 (to 54)
             12 UNPACK_SEQUENCE          2
             16 STORE_FAST               1 (i)
             18 STORE_FAST               2 (c)
             20 LOAD_FAST                2 (c)
             22 LOAD_DEREF               3 (key)
             24 LOAD_FAST                1 (i)
             26 LOAD_CONST               0 (32)
             28 BINARY_OP                6 (%)
             32 BINARY_SUBSCR
             42 BINARY_OP               12 (^)
             46 YIELD_VALUE
             48 RESUME                   1
             50 POP_TOP
             52 JUMP_BACKWARD           22 (to 10)
        >>   54 LOAD_CONST               1 (None)
             56 RETURN_VALUE

```

---

#### Step 6: Analyze the Payload Logic

The second-stage `payload` function does the following:

- Locates the `payload_dense/bias` tensor
- Takes the first 22 float values
- Multiplies by 255 and casts to `uint8`
- Converts to bytes

```python
bias = model.get_layer("payload_dense").get_weights()[1]
enc_flag_bytes = (bias[:22] * 255).astype("uint8")
print(list(enc_flag_bytes))
```

Output:
```
[128, 157, 115, 214, 41, 188, 25, 178, 114, 185, 167, 166, 119, 94, 207, 37, 200, 118, 213, 40, 96, 201]
```

This is the **ciphertext**.

---

#### Step 7: Decrypt the Flag

```python
cipher = [128, 157, 115, 214, 41, 188, 25, 178, 114, 185, 167, 166, 119, 94, 207, 37, 200, 118, 213, 40, 96, 201]
flag = bytes(c ^ key[i % 32] for i, c in enumerate(cipher))
print(flag.decode())
```
---
