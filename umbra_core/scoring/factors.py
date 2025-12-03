"""
================================================================================
                UMBRA CORE - Scoring Factors (scoring/factors.py)
================================================================================
Cálculo individualizado de cada fator de risco.
Cada função retorna um score normalizado (0.0 a 1.0+).
================================================================================
"""

import re
from typing import List, Dict, Set
from dataclasses import dataclass

from typing import TYPE_CHECKING

if TYPE_CHECKING:
      from umbra_core.scoring.weights import WeightConfig


@dataclass
class FactorResult:
    """Resultado do cálculo de um fator"""
    name: str
    score: float
    reason: str
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class ScoringFactors:
    """
    Calcula scores individuais para cada fator de análise.
    
    Cada método retorna um FactorResult com:
    - name: nome do fator
    - score: pontuação calculada
    - reason: explicação textual
    - details: dados adicionais
    """
    
    def __init__(self, config):
        """
        Args:
            config: Instância de WeightConfig
        """
        self.config = config
        
        # Cache de IPs conhecidos (simulação - em produção seria Redis/DB)
        self.ip_whitelist: Set[str] = set()
        self.ip_blacklist: Set[str] = set()
        self.known_ips: Dict[str, dict] = {}
    
    # ========================================================================
    #                    FATORES DE REPUTAÇÃO DE IP
    # ========================================================================
    
    def calculate_ip_reputation(self, event) -> FactorResult:
        """
        Calcula score de reputação do IP.
        
        Verifica:
        - Blacklist/Whitelist
        - IP conhecido vs desconhecido
        - Uso de Tor/Proxy
        - Risco geográfico
        """
        ip = event.source_ip
        score = 0.0
        reasons = []
        
        # Whitelist (penalidade forte)
        if ip in self.ip_whitelist:
            return FactorResult(
                name="ip_reputation",
                score=self.config.PENALTY_WHITELIST,
                reason="IP em whitelist",
                details={"ip": ip, "status": "whitelisted"}
            )
        
        # Blacklist (score máximo)
        if ip in self.ip_blacklist:
            return FactorResult(
                name="ip_reputation",
                score=self.config.IP_BLACKLISTED,
                reason="IP em blacklist conhecida",
                details={"ip": ip, "status": "blacklisted"}
            )
        
        # IP desconhecido
        if ip not in self.known_ips:
            score += self.config.IP_UNKNOWN
            reasons.append("IP nunca visto antes")
        
        # Risco geográfico
        if event.source_country:
            geo_risk = self.config.get_geo_risk(event.source_country)
            if geo_risk > 0:
                score += geo_risk
                reasons.append(f"País de risco: {event.source_country}")
        
        # TODO: Detectar Tor/Proxy (requer integração com serviços externos)
        # if self._is_tor_or_proxy(ip):
        #     score += self.config.IP_TOR_PROXY
        #     reasons.append("Uso de Tor/VPN/Proxy")
        
        reason_text = "; ".join(reasons) if reasons else "IP sem histórico suspeito"
        
        return FactorResult(
            name="ip_reputation",
            score=score,
            reason=reason_text,
            details={"ip": ip, "country": event.source_country}
        )
    
    # ========================================================================
    #                    FATORES DE COMPORTAMENTO
    # ========================================================================
    
    def calculate_behavior_score(self, event) -> FactorResult:
        """
        Calcula score de comportamento suspeito.
        
        Analisa:
        - Taxa de requisições
        - Diversidade de portas
        - Acesso sequencial (típico de scanners)
        """
        score = 0.0
        reasons = []
        details = {}
        
        # Taxa de requisições
        rate = event.request_rate
        details['request_rate'] = rate
        
        if rate > 50:
            score += self.config.RATE_HIGH
            reasons.append(f"Taxa muito alta: {rate:.1f} req/min")
        elif rate > 10:
            score += self.config.RATE_MEDIUM
            reasons.append(f"Taxa moderada: {rate:.1f} req/min")
        
        # Diversidade de portas
        num_ports = len(event.ports_scanned)
        details['ports_scanned'] = num_ports
        
        if num_ports > 10:
            score += self.config.PORT_DIVERSITY_HIGH
            reasons.append(f"Muitas portas escaneadas: {num_ports}")
        elif num_ports > 3:
            score += self.config.PORT_DIVERSITY_MEDIUM
            reasons.append(f"Múltiplas portas: {num_ports}")
        
        # Acesso sequencial (típico de Nmap)
        if event.sequential_access or self._is_sequential(event.ports_scanned):
            score += self.config.SEQUENTIAL_SCAN
            reasons.append("Acesso sequencial detectado (típico de scanner)")
            details['sequential'] = True
        
        reason_text = "; ".join(reasons) if reasons else "Comportamento normal"
        
        return FactorResult(
            name="behavior",
            score=score,
            reason=reason_text,
            details=details
        )
    
    def _is_sequential(self, ports: List[int]) -> bool:
        """Detecta se as portas foram acessadas sequencialmente"""
        if len(ports) < 3:
            return False
        
        sorted_ports = sorted(ports)
        sequential_count = 0
        
        for i in range(len(sorted_ports) - 1):
            if sorted_ports[i+1] - sorted_ports[i] == 1:
                sequential_count += 1
        
        # Se mais de 50% das portas são sequenciais, considera suspeito
        return sequential_count / len(sorted_ports) > 0.5
    
    # ========================================================================
    #                    FATORES DE PAYLOAD
    # ========================================================================
    
    def calculate_payload_score(self, event) -> FactorResult:
        """
        Calcula score de payload malicioso.
        
        Detecta:
        - SQL Injection
        - XSS
        - Path Traversal
        - Command Injection
        - Tamanho anormal
        """
        score = 0.0
        reasons = []
        details = {}
        
        payload = event.payload_sample.lower()
        
        # SQL Injection
        if event.contains_sql_injection or self._detect_sql_injection(payload):
            score += self.config.SQL_INJECTION
            reasons.append("SQL Injection detectado")
            details['sql_injection'] = True
        
        # XSS
        if event.contains_xss or self._detect_xss(payload):
            score += self.config.XSS_ATTEMPT
            reasons.append("XSS detectado")
            details['xss'] = True
        
        # Path Traversal
        if event.contains_path_traversal or self._detect_path_traversal(payload):
            score += self.config.PATH_TRAVERSAL
            reasons.append("Path Traversal detectado")
            details['path_traversal'] = True
        
        # Command Injection
        if self._detect_command_injection(payload):
            score += self.config.COMMAND_INJECTION
            reasons.append("Command Injection detectado")
            details['command_injection'] = True
        
        # Tamanho anormal
        size = event.payload_size
        if size > 10000:
            score += self.config.PAYLOAD_TOO_LARGE
            reasons.append(f"Payload muito grande: {size} bytes")
        elif size > 0 and size < 10:
            score += self.config.PAYLOAD_TOO_SMALL
            reasons.append(f"Payload muito pequeno: {size} bytes")
        
        reason_text = "; ".join(reasons) if reasons else "Payload normal"
        
        return FactorResult(
            name="payload",
            score=score,
            reason=reason_text,
            details=details
        )
    
    def _detect_sql_injection(self, payload: str) -> bool:
        """Detecta padrões comuns de SQL Injection"""
        sql_patterns = [
            r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",  # OR 1=1
            r"union\s+select",
            r";\s*drop\s+table",
            r";\s*exec(\s+|\()",
            r"'\s*or\s+'.*'='",  # ' OR '1'='1
        ]
        return any(re.search(pattern, payload, re.IGNORECASE) for pattern in sql_patterns)
    
    def _detect_xss(self, payload: str) -> bool:
        """Detecta padrões comuns de XSS"""
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe",
        ]
        return any(re.search(pattern, payload, re.IGNORECASE) for pattern in xss_patterns)
    
    def _detect_path_traversal(self, payload: str) -> bool:
        """Detecta padrões de Path Traversal"""
        return "../" in payload or "..%2f" in payload or "..%5c" in payload
    
    def _detect_command_injection(self, payload: str) -> bool:
        """Detecta padrões de Command Injection"""
        cmd_patterns = [
            r";\s*ls\s",
            r";\s*cat\s",
            r";\s*rm\s",
            r"\|\s*wget",
            r"\|\s*curl",
            r"`.*`",  # Backticks
            r"\$\(.*\)",  # $(command)
        ]
        return any(re.search(pattern, payload, re.IGNORECASE) for pattern in cmd_patterns)
    
    # ========================================================================
    #                    FATORES TEMPORAIS
    # ========================================================================
    
    def calculate_temporal_score(self, event) -> FactorResult:
        """
        Calcula score de padrão temporal suspeito.
        
        Analisa:
        - Horário de acesso
        - Dia da semana
        """
        score = 0.0
        reasons = []
        
        # Horário suspeito (0h-6h)
        if 0 <= event.hour_of_day < 6:
            score += self.config.SUSPICIOUS_HOUR
            reasons.append(f"Acesso em horário incomum: {event.hour_of_day}h")
        
        # Fim de semana
        if event.is_weekend:
            score += self.config.WEEKEND_ACCESS
            reasons.append("Acesso em fim de semana")
        
        reason_text = "; ".join(reasons) if reasons else "Padrão temporal normal"
        
        return FactorResult(
            name="temporal",
            score=score,
            reason=reason_text,
            details={'hour': event.hour_of_day, 'weekend': event.is_weekend}
        )
    
    # ========================================================================
    #                    FATORES DE FINGERPRINTING
    # ========================================================================
    
    def calculate_fingerprint_score(self, event) -> FactorResult:
        """
        Calcula score de fingerprinting suspeito.
        
        Analisa:
        - User-Agent
        - Headers HTTP
        """
        score = 0.0
        reasons = []
        details = {}
        
        # User-Agent de scanner
        if event.user_agent and self.config.is_scanner_user_agent(event.user_agent):
            score += self.config.SCANNER_USER_AGENT
            reasons.append(f"User-Agent de scanner: {event.user_agent[:50]}")
            details['scanner_ua'] = True
        
        # User-Agent vazio
        elif not event.user_agent or event.user_agent.strip() == "":
            score += self.config.EMPTY_USER_AGENT
            reasons.append("User-Agent vazio")
            details['empty_ua'] = True
        
        # Headers essenciais ausentes
        if event.http_headers:
            missing = self._check_missing_headers(event.http_headers)
            if missing:
                score += self.config.MISSING_HEADERS
                reasons.append(f"Headers ausentes: {', '.join(missing)}")
                details['missing_headers'] = missing
        
        reason_text = "; ".join(reasons) if reasons else "Fingerprint normal"
        
        return FactorResult(
            name="fingerprint",
            score=score,
            reason=reason_text,
            details=details
        )
    
    def _check_missing_headers(self, headers: Dict[str, str]) -> List[str]:
        """Verifica se headers essenciais estão ausentes"""
        essential_headers = ['host', 'accept']
        missing = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header in essential_headers:
            if header not in headers_lower:
                missing.append(header)
        
        return missing


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    from weights import WeightConfig
    
    # Simula um evento (em produção viria do Event model)
    class MockEvent:
        source_ip = "192.168.1.100"
        source_country = "CN"
        request_rate = 150.0
        ports_scanned = [21, 22, 23, 80, 443]
        sequential_access = True
        payload_sample = "?id=1' OR '1'='1"
        payload_size = 256
        contains_sql_injection = True
        contains_xss = False
        contains_path_traversal = False
        hour_of_day = 3
        is_weekend = False
        user_agent = "nmap scripting engine"
        http_headers = {}
    
    config = WeightConfig()
    factors = ScoringFactors(config)
    
    print("=" * 80)
    print("UMBRA CORE - Teste de Scoring Factors")
    print("=" * 80)
    print()
    
    # Testa cada fator
    ip_result = factors.calculate_ip_reputation(MockEvent())
    print(f"🌐 IP Reputation: {ip_result.score:.2f}")
    print(f"   Razão: {ip_result.reason}")
    print()
    
    behavior_result = factors.calculate_behavior_score(MockEvent())
    print(f"⚡ Behavior: {behavior_result.score:.2f}")
    print(f"   Razão: {behavior_result.reason}")
    print()
    
    payload_result = factors.calculate_payload_score(MockEvent())
    print(f"💣 Payload: {payload_result.score:.2f}")
    print(f"   Razão: {payload_result.reason}")
    print()
    
    temporal_result = factors.calculate_temporal_score(MockEvent())
    print(f"🕐 Temporal: {temporal_result.score:.2f}")
    print(f"   Razão: {temporal_result.reason}")
    print()
    
    fingerprint_result = factors.calculate_fingerprint_score(MockEvent())
    print(f"🔍 Fingerprint: {fingerprint_result.score:.2f}")
    print(f"   Razão: {fingerprint_result.reason}")
