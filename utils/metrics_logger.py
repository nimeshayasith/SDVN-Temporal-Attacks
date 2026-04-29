import os
import math
import csv
from typing import Sequence, Any, Dict

try:
    import numpy as _np
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    _HAS_SKL = True
except Exception:
    _HAS_SKL = False


class MetricTracker:
    """Simple metric tracker for regression and classification.

    Usage:
      tracker = MetricTracker(csv_path, save_every=1)
      tracker.update(epoch, step, phase, y_true, y_pred, is_classification=False)
      tracker.save_if_needed(epoch)
    """

    HEADER = ['epoch', 'step', 'phase',
              'mae', 'rmse', 'mape', 'r2',
              'accuracy', 'precision', 'recall', 'f1']

    def __init__(self, csv_path: str, save_every: int = 1, mode: str = 'w'):
        self.csv_path = csv_path
        self.save_every = max(1, int(save_every))
        self.rows = []  # buffer

        parent = os.path.dirname(csv_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        if mode == 'w' or (mode == 'a' and not os.path.exists(csv_path)):
            with open(self.csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(self.HEADER)

    @staticmethod
    def _to_np(x: Sequence[Any]):
        if _HAS_SKL:
            return _np.asarray(x)
        try:
            return _np.asarray(x)
        except Exception:
            # fallback: convert to list then np
            return _np.array(list(x))

    @classmethod
    def regression_metrics(cls, y_true, y_pred) -> Dict[str, float]:
        y_t = cls._to_np(y_true)
        y_p = cls._to_np(y_pred)
        # Ensure shapes line up
        if y_t.shape != y_p.shape:
            y_p = y_p.reshape(y_t.shape)

        if _HAS_SKL:
            mae = float(mean_absolute_error(y_t, y_p))
            rmse = float(math.sqrt(mean_squared_error(y_t, y_p)))
            r2 = float(r2_score(y_t, y_p))
        else:
            mae = float((abs(y_t - y_p)).mean())
            rmse = float(((y_t - y_p) ** 2).mean() ** 0.5)
            denom = ((y_t - y_t.mean()) ** 2).sum()
            r2 = float(1.0 - (((y_t - y_p) ** 2).sum() / (denom + 1e-12)))

        denom = (abs(y_t) + 1e-12)
        mape = float((abs((y_t - y_p) / denom)).mean()) * 100.0
        return {'mae': mae, 'rmse': rmse, 'mape': mape, 'r2': r2}

    @classmethod
    def classification_metrics(cls, y_true, y_pred) -> Dict[str, float]:
        y_t = cls._to_np(y_true)
        y_p = cls._to_np(y_pred)
        # Convert probabilities to labels if needed
        if y_p.ndim > 1 and y_p.shape[1] > 1:
            y_p = y_p.argmax(axis=1)

        if _HAS_SKL:
            acc = float(accuracy_score(y_t, y_p))
            prec = float(precision_score(y_t, y_p, average='macro', zero_division=0))
            rec = float(recall_score(y_t, y_p, average='macro', zero_division=0))
            f1 = float(f1_score(y_t, y_p, average='macro', zero_division=0))
        else:
            acc = float((y_t == y_p).mean())
            prec = rec = f1 = 0.0

        return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1}

    def compute_row(self, epoch: int, step: int, phase: str, y_true, y_pred, is_classification: bool):
        row = {'epoch': epoch, 'step': step, 'phase': phase}
        if is_classification:
            clsm = self.classification_metrics(y_true, y_pred)
            row.update({'mae': '', 'rmse': '', 'mape': '', 'r2': ''})
            row.update(clsm)
        else:
            reg = self.regression_metrics(y_true, y_pred)
            row.update(reg)
            row.update({'accuracy': '', 'precision': '', 'recall': '', 'f1': ''})
        return row

    def update(self, epoch: int, step: int, phase: str, y_true, y_pred, is_classification: bool = False, save_immediately: bool = False):
        """Add a measurement to the internal buffer.

        If save_immediately=True the rows buffer is flushed to disk right away.
        """
        row = self.compute_row(epoch, step, phase, y_true, y_pred, is_classification)
        self.rows.append(row)
        if save_immediately:
            self._flush_rows()

    def save_if_needed(self, epoch: int):
        if (epoch % self.save_every) == 0:
            self._flush_rows()

    def _flush_rows(self):
        if not self.rows:
            return
        with open(self.csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            for r in self.rows:
                writer.writerow([
                    r['epoch'], r['step'], r['phase'],
                    r.get('mae', ''), r.get('rmse', ''), r.get('mape', ''), r.get('r2', ''),
                    r.get('accuracy', ''), r.get('precision', ''), r.get('recall', ''), r.get('f1', ''),
                ])
        self.rows = []
