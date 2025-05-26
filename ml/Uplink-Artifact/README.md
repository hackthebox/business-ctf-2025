
# Uplink Artifact

### Description:
During an analysis of a compromised satellite uplink, a suspicious dataset was recovered. Intelligence indicates it may encode physical access credentials hidden within the spatial structure of Volnaya’s covert data infrastructure.

---

### Objective:
* Analyze the 3D dataset.
* Identify the cluster that holds meaningful structure.
* Decode the QR-like point pattern to retrieve the flag.

---

### Difficulty:
* `Very Easy`

---

### Challenge:
You’re given a CSV file containing thousands of 3D points, each labeled with a class. Only one class contains structured intelligence: a hidden QR code that must be visually reconstructed and scanned.

1. Load the dataset using pandas.
2. Visualize the full dataset in 3D.
3. Filter by class to investigate individual clusters.
4. When you find a plane-like class, project it into 2D.
5. Generate a high-resolution scatterplot.
6. Scan the output QR to retrieve the flag.

---

### Files Provided:
- `uplink_spatial_auth.csv`

---

### Solver:

#### Step 1: Load the dataset
```python
import pandas as pd
df = pd.read_csv("uplink_spatial_auth.csv")
```

#### Step 2: Visualize in 3D (first inspection)
```python
import plotly.express as px

fig = px.scatter_3d(df, x='x', y='y', z='z', color='label', opacity=0.7)
fig.show()
```
![png](assets/image.png)

From this, one class clearly appears “flat” and suspicious. Like a qr code.

---

#### Step 3: Focus on class 1 and visualize
```python
import matplotlib.pyplot as plt

qr_points = df[df['label'] == 1]
plt.figure(figsize=(6, 6))
plt.scatter(qr_points['x'], qr_points['y'], s=400, c='black')
plt.gca().invert_yaxis()
plt.axis('off')
plt.tight_layout()
plt.savefig("qr_projection.png")
plt.show()
```
![png](assets/image2.png)
---

#### Step 4: Decode the QR image

This will give us the flag.
