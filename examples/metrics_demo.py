"""Small demo showing how to use MetricTracker and save metrics periodically.

Run this from PowerShell:

    python .\examples\metrics_demo.py

It will create `results/metrics_demo.csv` under the project folder and append rows every epoch.
"""
from pathlib import Path
import sys
import os
import numpy as np

# Make sure project root is on sys.path so local `utils` package can be imported
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from utils.metrics_logger import MetricTracker


def synthetic_regression_batch(batch_size=32):
    x = np.linspace(0, 10, batch_size)
    noise = np.random.normal(scale=0.5, size=batch_size)
    y = 2.0 * x + 1.0 + noise
    # pretend predictions are slightly off
    y_pred = 2.0 * x + 1.0 + np.random.normal(scale=0.8, size=batch_size)
    return y, y_pred


def run_demo(csv_path: str, epochs: int = 5, batches_per_epoch: int = 3):
    tracker = MetricTracker(csv_path=csv_path, save_every=1, mode='w')

    for epoch in range(1, epochs + 1):
        for step in range(1, batches_per_epoch + 1):
            y_true, y_pred = synthetic_regression_batch(batch_size=64)
            tracker.update(epoch=epoch, step=step, phase='train',
                           y_true=y_true, y_pred=y_pred, is_classification=False)

        # At the end of epoch do a validation measurement (single large batch)
        y_true_val, y_pred_val = synthetic_regression_batch(batch_size=512)
        tracker.update(epoch=epoch, step=0, phase='val',
                       y_true=y_true_val, y_pred=y_pred_val, is_classification=False)

        # Save metrics to disk every epoch (save_every=1)
        tracker.save_if_needed(epoch)
        print(f"Epoch {epoch} metrics written to {csv_path}")


if __name__ == '__main__':
    project_root = Path(__file__).resolve().parents[1]
    out = project_root / 'results' / 'metrics_demo.csv'
    run_demo(str(out), epochs=5, batches_per_epoch=4)
