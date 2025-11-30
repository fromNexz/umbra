"""
Scoring - Sistema de pontuação e análise de risco
"""

from umbra_core.scoring.weights import WeightConfig
from umbra_core.scoring.factors import ScoringFactors, FactorResult
from umbra_core.scoring.engine import ScoringEngine, ScoringResult

__all__ = [
    'WeightConfig',
    'ScoringFactors',
    'FactorResult',
    'ScoringEngine',
    'ScoringResult',
]