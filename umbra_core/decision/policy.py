"""
================================================================================
                UMBRA CORE - Decision Policy (decision/policy.py)
================================================================================
Traduz scores em ações concretas (ALLOW, BLOCK, REDIRECT, etc).
Define as políticas de resposta do sistema.
================================================================================
"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass


class Action(Enum):
    """Ações possíveis que o sistema pode tomar"""
    ALLOW = "allow"                    # Permite a requisição normalmente
    MONITOR = "monitor"                # Permite mas loga detalhadamente
    RATE_LIMIT = "rate_limit"          # Aplica rate limiting
    ENCRYPT = "encrypt"                # Criptografa a resposta
    REDIRECT = "redirect"              # Redireciona para honeypot
    BLOCK_TEMPORARY = "block_temp"     # Bloqueia temporariamente (ex: 1h)
    BLOCK_PERMANENT = "block_perm"     # Bloqueia permanentemente
    CAPTCHA = "captcha"                # Exige CAPTCHA antes de prosseguir


@dataclass
class Decision:
    """
    Decisão tomada pelo sistema de política.
    
    Attributes:
        action: Ação a ser executada
        reason: Motivo da decisão
        score: Score que gerou a decisão
        severity: Nível de severidade
        metadata: Metadados adicionais (ex: tempo de bloqueio, URL de redirect)
        recommended_duration_seconds: Duração recomendada (para bloqueios)
    """
    action: Action
    reason: str
    score: float
    severity: str
    metadata: Dict[str, Any] = None
    recommended_duration_seconds: Optional[int] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict:
        """Converte para dicionário JSON-serializável"""
        return {
            'action': self.action.value,
            'reason': self.reason,
            'score': round(self.score, 3),
            'severity': self.severity,
            'metadata': self.metadata,
            'recommended_duration_seconds': self.recommended_duration_seconds,
        }
    
    def __repr__(self) -> str:
        return (
            f"Decision(action={self.action.value}, "
            f"severity={self.severity}, "
            f"score={self.score:.2f})"
        )


class PolicyEngine:
    """
    Motor de políticas que decide a ação baseado no score.
    
    Workflow:
    1. Recebe ScoringResult
    2. Analisa score e severidade
    3. Aplica regras de política
    4. Retorna Decision com ação a executar
    """
    
    def __init__(self, config):
        """
        Args:
            config: Instância de WeightConfig
        """
        self.config = config
        
        # Configurações de duração de bloqueio (em segundos)
        self.block_durations = {
            'medium': 300,          # 5 minutos
            'high': 3600,           # 1 hora
            'critical': 86400,      # 24 horas
            'malicious': None,      # Permanente
        }
        
        # Contador de decisões (para estatísticas)
        self.decision_counts = {action: 0 for action in Action}
    
    def make_decision(self, scoring_result) -> Decision:
        """
        Toma uma decisão baseada no resultado do scoring.
        
        Args:
            scoring_result: Instância de ScoringResult
            
        Returns:
            Decision com a ação a ser executada
        """
        score = scoring_result.final_score
        severity = scoring_result.severity
        
        # ====================================================================
        #                    POLÍTICAS POR SEVERIDADE
        # ====================================================================
        
        # SAFE (score < 0.0) → ALLOW
        if severity == "safe":
            decision = Decision(
                action=Action.ALLOW,
                reason="Tráfego confiável (whitelisted ou score negativo)",
                score=score,
                severity=severity,
                metadata={'confidence': 'high'}
            )
        
        # LOW (0.0 - 0.3) → ALLOW
        elif severity == "low":
            decision = Decision(
                action=Action.ALLOW,
                reason="Risco baixo, tráfego normal",
                score=score,
                severity=severity,
                metadata={'confidence': 'medium'}
            )
        
        # MEDIUM (0.3 - 0.7) → MONITOR
        elif severity == "medium":
            decision = Decision(
                action=Action.MONITOR,
                reason="Risco médio, monitoramento ativado",
                score=score,
                severity=severity,
                metadata={
                    'log_level': 'info',
                    'alert_threshold': 3,  # Alerta após 3 eventos similares
                }
            )
        
        # HIGH (0.7 - 1.0) → ENCRYPT ou REDIRECT
        elif severity == "high":
            # Decisão baseada no tipo de ataque
            if self._is_reconnaissance(scoring_result):
                # Port scan → Redireciona para honeypot
                decision = Decision(
                    action=Action.REDIRECT,
                    reason="Tentativa de reconhecimento detectada, redirecionando para honeypot",
                    score=score,
                    severity=severity,
                    metadata={
                        'redirect_url': 'honeypot.internal',
                        'log_all_activity': True,
                    }
                )
            else:
                # Outros ataques → Criptografa resposta
                decision = Decision(
                    action=Action.ENCRYPT,
                    reason="Risco alto, resposta será criptografada",
                    score=score,
                    severity=severity,
                    metadata={
                        'encryption_method': 'aes-128',
                        'require_key': True,
                    }
                )
        
        # CRITICAL (1.0 - 1.5) → RATE_LIMIT ou CAPTCHA
        elif severity == "critical":
            if self._is_automated_attack(scoring_result):
                # Ataque automatizado → CAPTCHA
                decision = Decision(
                    action=Action.CAPTCHA,
                    reason="Ataque automatizado detectado, CAPTCHA obrigatório",
                    score=score,
                    severity=severity,
                    metadata={
                        'captcha_difficulty': 'medium',
                        'max_attempts': 3,
                    }
                )
            else:
                # Ataque manual → Rate Limit
                decision = Decision(
                    action=Action.RATE_LIMIT,
                    reason="Risco crítico, rate limiting aplicado",
                    score=score,
                    severity=severity,
                    metadata={
                        'max_requests': 5,
                        'window_seconds': 60,
                    },
                    recommended_duration_seconds=self.block_durations['critical']
                )
        
        # MALICIOUS (> 1.5) → BLOCK
        else:  # malicious
            # Decide entre bloqueio temporário ou permanente
            if score > 2.5:
                # Score muito alto → Bloqueio permanente
                decision = Decision(
                    action=Action.BLOCK_PERMANENT,
                    reason="Atividade altamente maliciosa detectada, bloqueio permanente",
                    score=score,
                    severity=severity,
                    metadata={
                        'blacklist_ip': True,
                        'notify_admin': True,
                    },
                    recommended_duration_seconds=self.block_durations['malicious']
                )
            else:
                # Score alto mas não extremo → Bloqueio temporário
                decision = Decision(
                    action=Action.BLOCK_TEMPORARY,
                    reason="Atividade maliciosa detectada, bloqueio temporário",
                    score=score,
                    severity=severity,
                    metadata={
                        'retry_after_seconds': self.block_durations['critical'],
                    },
                    recommended_duration_seconds=self.block_durations['critical']
                )
        
        # Atualiza contadores
        self.decision_counts[decision.action] += 1
        
        return decision
    
    def _is_reconnaissance(self, scoring_result) -> bool:
        """
        Detecta se é uma tentativa de reconhecimento (port scan, etc).
        
        Args:
            scoring_result: Resultado do scoring
            
        Returns:
            True se for reconhecimento
        """
        # Verifica se o score de behavior é alto (indicando scan)
        behavior_score = scoring_result.dimension_scores.get('behavior', 0)
        
        # Verifica se payload score é baixo (apenas probing, sem exploit)
        payload_score = scoring_result.dimension_scores.get('payload', 0)
        
        return behavior_score > 1.0 and payload_score < 0.5
    
    def _is_automated_attack(self, scoring_result) -> bool:
        """
        Detecta se é um ataque automatizado (bot, scanner).
        
        Args:
            scoring_result: Resultado do scoring
            
        Returns:
            True se for automatizado
        """
        # Verifica fingerprint suspeito (scanner UA, headers ausentes)
        fingerprint_score = scoring_result.dimension_scores.get('fingerprint', 0)
        
        # Alta taxa de requisições
        for detail in scoring_result.factor_details:
            if detail['dimension'] == 'behavior':
                rate = detail['details'].get('request_rate', 0)
                if rate > 50:  # > 50 req/min é muito suspeito
                    return True
        
        return fingerprint_score > 0.5
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas de decisões tomadas"""
        total = sum(self.decision_counts.values())
        
        stats = {
            'total_decisions': total,
            'decisions_by_action': {
                action.value: count 
                for action, count in self.decision_counts.items()
            },
        }
        
        # Calcula percentuais
        if total > 0:
            stats['percentages'] = {
                action.value: round(count / total * 100, 2)
                for action, count in self.decision_counts.items()
            }
        
        return stats


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    from weights import WeightConfig
    
    # Simula ScoringResult
    class MockScoringResult:
        def __init__(self, score, severity):
            self.event_id = "test-001"
            self.final_score = score
            self.severity = severity
            self.dimension_scores = {
                'ip_reputation': 0.5,
                'behavior': 1.2,
                'payload': 0.8,
                'temporal': 0.3,
                'fingerprint': 0.6,
            }
            self.factor_details = [
                {
                    'dimension': 'behavior',
                    'details': {'request_rate': 120.0}
                }
            ]
    
    config = WeightConfig()
    policy = PolicyEngine(config)
    
    print("=" * 80)
    print("UMBRA CORE - Teste do Policy Engine")
    print("=" * 80)
    print()
    
    # Testa diferentes cenários
    scenarios = [
        (-1.0, "safe", "IP whitelisted"),
        (0.2, "low", "Tráfego normal"),
        (0.5, "medium", "Suspeita moderada"),
        (0.9, "high", "Reconhecimento detectado"),
        (1.2, "critical", "Ataque automatizado"),
        (2.0, "malicious", "SQL Injection"),
        (3.0, "malicious", "Múltiplos ataques"),
    ]
    
    for score, severity, description in scenarios:
        result = MockScoringResult(score, severity)
        decision = policy.make_decision(result)
        
        print(f"📋 CENÁRIO: {description}")
        print(f"   Score: {score:.1f} | Severidade: {severity}")
        print(f"   ➜ Ação: {decision.action.value.upper()}")
        print(f"   ➜ Razão: {decision.reason}")
        if decision.recommended_duration_seconds:
            duration = decision.recommended_duration_seconds
            print(f"   ➜ Duração: {duration}s ({duration/3600:.1f}h)")
        print()
    
    print("=" * 80)
    print("📊 ESTATÍSTICAS DE DECISÕES")
    print("=" * 80)
    stats = policy.get_stats()
    print(f"Total de decisões: {stats['total_decisions']}")
    print()
    for action, count in stats['decisions_by_action'].items():
        if count > 0:
            pct = stats['percentages'][action]
            print(f"  • {action:20s}: {count:3d} ({pct:5.1f}%)")