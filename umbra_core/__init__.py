"""
================================================================================
                    UMBRA CORE - __init__.py Files
================================================================================
Arquivos de inicialização para todos os módulos.
Facilita as importações e expõe a API pública do sistema.
================================================================================
"""

# ============================================================================
#                    umbra_core/__init__.py
# ============================================================================

"""
Umbra Core - Sistema de Proteção Cibernética

Um sistema de análise e decisão baseado em scoring matemático para
detecção e prevenção de ataques cibernéticos.

Uso básico:
    from umbra_core import UmbraCore
    
    umbra = UmbraCore()
    result = umbra.process_event(event)
"""

__version__ = "0.1.0"
__author__ = "Umbra Security Team"

# Importações principais para facilitar o uso
from umbra_core.config import UmbraConfig
from umbra_core.models.event import Event, EventType, Severity
from umbra_core.scoring.weights import WeightConfig
from umbra_core.scoring.factors import ScoringFactors
from umbra_core.scoring.engine import ScoringEngine
from umbra_core.decision.policy import PolicyEngine, Action, Decision
from umbra_core.storage.event_logger import EventLogger

__all__ = [
    'UmbraConfig',
    'Event',
    'EventType',
    'Severity',
    'WeightConfig',
    'ScoringFactors',
    'ScoringEngine',
    'PolicyEngine',
    'Action',
    'Decision',
    'EventLogger',
]


# ============================================================================
#                    umbra_core/models/__init__.py
# ============================================================================

"""
Models - Modelos de dados do sistema
"""

from umbra_core.models.event import Event, EventType, Severity

__all__ = ['Event', 'EventType', 'Severity']


# ============================================================================
#                    umbra_core/scoring/__init__.py
# ============================================================================

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


# ============================================================================
#                    umbra_core/decision/__init__.py
# ============================================================================

"""
Decision - Sistema de políticas e tomada de decisão
"""

from umbra_core.decision.policy import PolicyEngine, Action, Decision

__all__ = ['PolicyEngine', 'Action', 'Decision']


# ============================================================================
#                    umbra_core/storage/__init__.py
# ============================================================================

"""
Storage - Sistema de armazenamento e logging
"""

from umbra_core.storage.event_logger import EventLogger

__all__ = ['EventLogger']


# ============================================================================
#                    umbra_core/events/__init__.py
# ============================================================================

"""
Events - Processadores de eventos (para futuro uso)
"""

__all__ = []


# ============================================================================
#                    INSTRUÇÕES DE CRIAÇÃO DOS ARQUIVOS
# ============================================================================

"""
IMPORTANTE: Crie os seguintes arquivos vazios ou com o conteúdo acima:

1. umbra_core/__init__.py  (usar conteúdo da seção correspondente)
2. umbra_core/models/__init__.py
3. umbra_core/scoring/__init__.py
4. umbra_core/decision/__init__.py
5. umbra_core/storage/__init__.py
6. umbra_core/events/__init__.py

Estrutura final:

umbra_core/
├── __init__.py                    ← Importa componentes principais
├── config.py                      ← Configuração global
├── models/
│   ├── __init__.py                ← Exporta Event, EventType, Severity
│   └── event.py
├── scoring/
│   ├── __init__.py                ← Exporta WeightConfig, Factors, Engine
│   ├── weights.py
│   ├── factors.py
│   └── engine.py
├── decision/
│   ├── __init__.py                ← Exporta PolicyEngine, Action, Decision
│   └── policy.py
├── storage/
│   ├── __init__.py                ← Exporta EventLogger
│   └── event_logger.py
└── events/
    └── __init__.py                ← Vazio (para futuro)

Com isso, você pode importar facilmente:

    from umbra_core import Event, ScoringEngine, PolicyEngine
    from umbra_core.config import UmbraConfig
"""

print(__doc__)