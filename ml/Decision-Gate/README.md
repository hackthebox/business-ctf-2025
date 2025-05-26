# Decision-Gate

### Description:
During a breach into a Volnayan AI research node, Task Force Phoenix uncovered a dormant decision system—its logic locked behind a concealed execution path. Intelligence suggests it was used to authorize classified operations. The correct path must be uncovered before it's lost to blackout.

### Objective:
* Reverse-engineer the model to discover the unique input that triggers the prediction `UNLOCK_FLAG_PATH`.
* This input must be crafted by tracing the logic of the tree itself.

### Difficulty:
* `Medium`

### Challenge:
You're given a `DecisionTreeClassifier` model and a sample input vector. Nothing else. You must:
1. Load and inspect the model.
2. Analyze the decision tree structure.
3. Discover all possible class labels.
4. Identify the path that leads to a suspicious target class.
5. Construct a synthetic input that satisfies the tree logic for that path.
6. Use this vector to trigger the flag.

**Files provided:**
- `tree_model.joblib`  
- `example_input.npy`

---

### Solver:


#### Step 1: Load the model and explore input shape
```python
from joblib import load
import numpy as np

model = load("tree_model.joblib")
example = np.load("example_input.npy")

print("Example shape:", example.shape)  # Expecting (1, 5)
```
We now know the model expects a 5D float input vector.

---

#### Step 2: Inspect the tree structure
```python
tree = model.tree_
print("Tree depth:", model.get_depth())
print("Total nodes:", tree.node_count)
```
Useful to get a sense of tree complexity.

---

#### Step 3: List all predicted labels
```python
print("Model class labels:", model.classes_)
```
If we see something like:
```
['class_001', 'class_257', ..., 'UNLOCK_FLAG_PATH']
```
Bingo. `UNLOCK_FLAG_PATH` clearly stands out.

---

#### Step 4: Find the leaf that predicts the target label
```python
target_label = "UNLOCK_FLAG_PATH"
for i in range(tree.node_count):
    if tree.children_left[i] == tree.children_right[i]:  # it's a leaf
        class_idx = tree.value[i][0].argmax()
        label = model.classes_[class_idx]
        if label == target_label:
            print("Found label at leaf node:", i)
            target_leaf = i
            break
else:
    raise Exception("Label not found")
```

---

#### Step 5: Trace the decision path
```python
def get_parents(tree):
    parents = [-1] * tree.node_count
    for i in range(tree.node_count):
        for child in (tree.children_left[i], tree.children_right[i]):
            if child != -1:
                parents[child] = i
    return parents

def trace_path(tree, leaf_id):
    parents = get_parents(tree)
    path = []
    node = leaf_id
    while parents[node] != -1:
        parent = parents[node]
        feat = tree.feature[parent]
        thresh = tree.threshold[parent]
        is_left = (tree.children_left[parent] == node)
        path.append((feat, thresh, is_left))
        node = parent
    return path[::-1]  # root to leaf

path = trace_path(tree, target_leaf)
```

---

#### Step 6: Build a satisfying input
```python
x = np.zeros(model.n_features_in_)
for feat, thresh, go_left in path:
    x[feat] = thresh - 1e-4 if go_left else thresh + 1e-4

print("Reconstructed input vector:", ",".join(map(str, x)))
```

---

#### Step 7: Predict and trigger the model
```python
pred = model.predict([x])[0]
print("Prediction:", pred)
```
If you see:
```
Prediction: UNLOCK_FLAG_PATH
```
Success! You've reconstructed the one valid input.

Submit this to the validator to receive the flag.
