from __future__ import annotations

from typing import List, Dict, Optional

import numpy as np
from PyQt6.QtCore import QObject, pyqtSignal

from ...core.game_data.modules.enhanced_fast_simulator import run_simulation_numpy


class SimulatorWorker(QObject):
    progress_updated = pyqtSignal(int)
    simulation_finished = pyqtSignal(dict)
    partial_results = pyqtSignal(object)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._targets: List[Dict] | None = None
        self._pity: int = 150
        self._num_sims: int = 10_000
        self._confidence: int = 95

    def start_simulation(self, targets: List[Dict], pity: int, num_sims: int, confidence: int) -> None:
        self._targets = list(targets or [])
        self._pity = int(pity)
        self._num_sims = max(1, int(num_sims))
        self._confidence = max(1, min(99, int(confidence)))

    def run(self) -> None:
        if not self._targets or self._num_sims <= 0:
            self.simulation_finished.emit({
                "gems_spent": np.array([], dtype=np.int32),
                "percentile_gems": 0,
                "confidence": self._confidence,
            })
            return

        gems_spent = run_simulation_numpy(
            num_sims=self._num_sims,
            targets=self._targets,
            pity_limit=self._pity,
            progress_callback=lambda p: self.progress_updated.emit(int(p)),
            partial_results_callback=lambda arr: self.partial_results.emit(arr),
        )

        mean_gems = float(np.mean(gems_spent)) if gems_spent.size else 0.0
        percentile = float(np.percentile(gems_spent, self._confidence)) if gems_spent.size else 0.0

        results = {
            "gems_spent": gems_spent,
            "mean_gems": mean_gems,
            "percentile_gems": int(percentile),
            "confidence": int(self._confidence),
        }
        self.simulation_finished.emit(results)


