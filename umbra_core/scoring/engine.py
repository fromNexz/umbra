"""
================================================================================
                UMBRA CORE - Scoring Engine (scoring/engine.py)
================================================================================
Motor principal de cálculo de score.
Combina todos os fatores e aplica os pesos configurados.
================================================================================
"""

import time
from typing import Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class ScoringResult:
    """
    Resultado completo da análise de scoring.
    
    Attributes:
        event_id: ID do evento analisado
        final_score: Score final calculado (-2.0 a 3.0+)
        dimension_scores: Score de cada dimensão
        factor_details: Detalhes de cada fator calculado
        processing_time_ms: Tempo de processamento em milissegundos
        severity: Nível de severidade (baseado no score)
        triggered_rules: Regras que foram acionadas
    """
    event_id: str
    final_score: float
    dimension_scores: Dict[str, float] = field(default_factory=dict)
    factor_details: List[Dict] = field(default_factory=list)
    processing_time_ms: float = 0.0
    severity: str = "unknown"
    triggered_rules: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Converte para dicionário JSON-serializável"""
        return {
            'event_id': self.event_id,
            'final_score': round(self.final_score, 3),
            'severity': self.severity,
            'dimension_scores': {k: round(v, 3) for k, v in self.dimension_scores.items()},
            'factor_details': self.factor_details,
            'processing_time_ms': round(self.processing_time_ms, 2),
            'triggered_rules': self.triggered_rules,
        }


class ScoringEngine:
    """
    Motor de scoring que combina todos os fatores de análise.
    
    Workflow:
    1. Recebe um Event
    2. Calcula score de cada dimensão usando ScoringFactors
    3. Aplica pesos das dimensões (WeightConfig)
    4. Soma tudo para obter score final
    5. Aplica bônus e penalidades
    6. Retorna ScoringResult completo
    """
    
    def __init__(self, config, factors):
        """
        Args:
            config: Instância de WeightConfig
            factors: Instância de ScoringFactors
        """
        self.config = config
        self.factors = factors
        
        # Estatísticas (para monitoramento)
        self.total_events_processed = 0
        self.total_processing_time_ms = 0.0
        
        # Cache de scores (LRU simples - em produção usar Redis)
        self._score_cache = {}
        self._cache_hits = 0
        self._cache_misses = 0
    
    def calculate_score(self, event) -> ScoringResult:
        """
        Calcula o score completo de um evento.
        
        Args:
            event: Instância de Event
            
        Returns:
            ScoringResult com análise completa
        """
        start_time = time.perf_counter()
        
        # Inicializa resultado
        result = ScoringResult(event_id=event.event_id, final_score=0.0)
        
        # ====================================================================
        #                    ETAPA 1: Short-circuit checks
        # ====================================================================
        # Otimização: verifica whitelist/blacklist antes de calcular tudo
        
        # Whitelist → retorna imediatamente com score negativo
        if self._is_whitelisted(event):
            result.final_score = self.config.PENALTY_WHITELIST
            result.severity = "safe"
            result.triggered_rules.append("IP_WHITELISTED")
            result.processing_time_ms = (time.perf_counter() - start_time) * 1000
            return result
        
        # Blacklist → retorna imediatamente com score máximo
        if self._is_blacklisted(event):
            result.final_score = self.config.IP_BLACKLISTED
            result.severity = "malicious"
            result.triggered_rules.append("IP_BLACKLISTED")
            result.processing_time_ms = (time.perf_counter() - start_time) * 1000
            return result
        
        # ====================================================================
        #                    ETAPA 2: Calcular scores das dimensões
        # ====================================================================
        
        # 1. IP Reputation
        ip_result = self.factors.calculate_ip_reputation(event)
        ip_score = ip_result.score * self.config.get_dimension_weight('ip_reputation')
        result.dimension_scores['ip_reputation'] = ip_score
        result.factor_details.append({
            'dimension': 'ip_reputation',
            'raw_score': ip_result.score,
            'weighted_score': ip_score,
            'reason': ip_result.reason,
            'details': ip_result.details,
        })
        
        # 2. Behavior
        behavior_result = self.factors.calculate_behavior_score(event)
        behavior_score = behavior_result.score * self.config.get_dimension_weight('behavior')
        result.dimension_scores['behavior'] = behavior_score
        result.factor_details.append({
            'dimension': 'behavior',
            'raw_score': behavior_result.score,
            'weighted_score': behavior_score,
            'reason': behavior_result.reason,
            'details': behavior_result.details,
        })
        
        # ====================================================================
        #                    ETAPA 3: Early exit optimization
        # ====================================================================
        # Se já está muito alto, não precisa calcular o resto
        partial_score = ip_score + behavior_score
        
        if partial_score > self.config.THRESHOLD_CRITICAL:
            result.final_score = partial_score
            result.severity = self._calculate_severity(partial_score)
            result.triggered_rules.append("EARLY_EXIT_HIGH_SCORE")
            result.processing_time_ms = (time.perf_counter() - start_time) * 1000
            self._update_stats(result.processing_time_ms)
            return result
        
        # ====================================================================
        #                    ETAPA 4: Calcular dimensões restantes
        # ====================================================================
        
        # 3. Payload
        payload_result = self.factors.calculate_payload_score(event)
        payload_score = payload_result.score * self.config.get_dimension_weight('payload')
        result.dimension_scores['payload'] = payload_score
        result.factor_details.append({
            'dimension': 'payload',
            'raw_score': payload_result.score,
            'weighted_score': payload_score,
            'reason': payload_result.reason,
            'details': payload_result.details,
        })
        
        # 4. Temporal
        temporal_result = self.factors.calculate_temporal_score(event)
        temporal_score = temporal_result.score * self.config.get_dimension_weight('temporal')
        result.dimension_scores['temporal'] = temporal_score
        result.factor_details.append({
            'dimension': 'temporal',
            'raw_score': temporal_result.score,
            'weighted_score': temporal_score,
            'reason': temporal_result.reason,
            'details': temporal_result.details,
        })
        
        # 5. Fingerprint
        fingerprint_result = self.factors.calculate_fingerprint_score(event)
        fingerprint_score = fingerprint_result.score * self.config.get_dimension_weight('fingerprint')
        result.dimension_scores['fingerprint'] = fingerprint_score
        result.factor_details.append({
            'dimension': 'fingerprint',
            'raw_score': fingerprint_result.score,
            'weighted_score': fingerprint_score,
            'reason': fingerprint_result.reason,
            'details': fingerprint_result.details,
        })
        
        # ====================================================================
        #                    ETAPA 5: Calcular score final
        # ====================================================================
        
        base_score = sum(result.dimension_scores.values())
        
        # Aplicar bônus e penalidades
        bonuses = self._calculate_bonuses(event)
        penalties = self._calculate_penalties(event)
        
        result.final_score = base_score + bonuses - penalties
        
        # Adiciona regras acionadas
        if bonuses > 0:
            result.triggered_rules.append(f"BONUS_APPLIED_{bonuses:.2f}")
        if penalties > 0:
            result.triggered_rules.append(f"PENALTY_APPLIED_{penalties:.2f}")
        
        # ====================================================================
        #                    ETAPA 6: Finalizar resultado
        # ====================================================================
        
        result.severity = self._calculate_severity(result.final_score)
        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        
        # Atualiza estatísticas
        self._update_stats(result.processing_time_ms)
        
        return result
    
    def _is_whitelisted(self, event) -> bool:
        """Verifica se o IP está na whitelist"""
        return event.source_ip in self.factors.ip_whitelist
    
    def _is_blacklisted(self, event) -> bool:
        """Verifica se o IP está na blacklist"""
        return event.source_ip in self.factors.ip_blacklist
    
    def _calculate_bonuses(self, event) -> float:
        """
        Calcula bônus (agravam o score).
        
        Bônus são aplicados em situações especiais que aumentam a suspeita.
        """
        bonus = 0.0
        
        # Múltiplas técnicas de ataque
        attack_types = sum([
            event.contains_sql_injection,
            event.contains_xss,
            event.contains_path_traversal,
        ])
        
        if attack_types >= 2:
            bonus += self.config.BONUS_MULTIPLE_TECHNIQUES
        
        # TODO: Adicionar mais bônus conforme necessário
        # - Tentativa de explorar CVE conhecida
        # - Assinatura de malware
        # - IP já bloqueado anteriormente
        
        return bonus
    
    def _calculate_penalties(self, event) -> float:
        """
        Calcula penalidades (atenuam o score).
        
        Penalidades são aplicadas para reduzir falsos positivos.
        """
        penalty = 0.0
        
        # Token/API key válido (se implementado)
        if event.metadata.get('valid_token'):
            penalty += abs(self.config.PENALTY_VALID_TOKEN)
        
        # HTTPS válido
        if event.metadata.get('https_valid'):
            penalty += abs(self.config.PENALTY_HTTPS_VALID)
        
        return penalty
    
    def _calculate_severity(self, score: float) -> str:
        """
        Calcula o nível de severidade baseado no score.
        
        Args:
            score: Score calculado
            
        Returns:
            String representando a severidade
        """
        if score < self.config.THRESHOLD_SAFE:
            return "safe"
        elif score < self.config.THRESHOLD_LOW:
            return "low"
        elif score < self.config.THRESHOLD_MEDIUM:
            return "medium"
        elif score < self.config.THRESHOLD_HIGH:
            return "high"
        elif score < self.config.THRESHOLD_CRITICAL:
            return "critical"
        else:
            return "malicious"
    
    def _update_stats(self, processing_time_ms: float):
        """Atualiza estatísticas internas"""
        self.total_events_processed += 1
        self.total_processing_time_ms += processing_time_ms
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do engine"""
        avg_time = (self.total_processing_time_ms / self.total_events_processed 
                   if self.total_events_processed > 0 else 0)
        
        return {
            'total_events_processed': self.total_events_processed,
            'total_processing_time_ms': round(self.total_processing_time_ms, 2),
            'avg_processing_time_ms': round(avg_time, 2),
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'cache_hit_rate': (self._cache_hits / (self._cache_hits + self._cache_misses) * 100
                              if (self._cache_hits + self._cache_misses) > 0 else 0),
        }


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    from weights import WeightConfig
    from factors import ScoringFactors
    
    # Simula um evento malicioso
    class MockEvent:
        event_id = "test-001"
        source_ip = "203.0.113.45"
        source_country = "CN"
        request_rate = 150.0
        ports_scanned = [21, 22, 23, 80, 443, 3306, 8080]
        sequential_access = True
        payload_sample = "?id=1' UNION SELECT * FROM users--"
        payload_size = 512
        contains_sql_injection = True
        contains_xss = False
        contains_path_traversal = False
        hour_of_day = 3
        is_weekend = False
        user_agent = "nmap scripting engine"
        http_headers = {}
        metadata = {}
    
    # Inicializa engine
    config = WeightConfig()
    factors = ScoringFactors(config)
    engine = ScoringEngine(config, factors)
    
    print("=" * 80)
    print("UMBRA CORE - Teste do Scoring Engine")
    print("=" * 80)
    print()
    
    # Calcula score
    result = engine.calculate_score(MockEvent())
    
    print(f"🎯 RESULTADO DA ANÁLISE")
    print(f"   Event ID: {result.event_id}")
    print(f"   Score Final: {result.final_score:.3f}")
    print(f"   Severidade: {result.severity.upper()}")
    print(f"   Tempo de processamento: {result.processing_time_ms:.2f}ms")
    print()
    
    print(f"📊 SCORES POR DIMENSÃO:")
    for dim, score in result.dimension_scores.items():
        print(f"   • {dim:20s}: {score:.3f}")
    print()
    
    print(f"🔍 DETALHES DOS FATORES:")
    for detail in result.factor_details:
        print(f"   [{detail['dimension']}]")
        print(f"      Raw Score: {detail['raw_score']:.3f}")
        print(f"      Weighted: {detail['weighted_score']:.3f}")
        print(f"      Razão: {detail['reason']}")
        print()
    
    print(f"⚠️  REGRAS ACIONADAS:")
    for rule in result.triggered_rules:
        print(f"   • {rule}")
    print()
    
    print(f"📈 ESTATÍSTICAS DO ENGINE:")
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   • {key}: {value}")