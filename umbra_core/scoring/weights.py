"""
================================================================================
                UMBRA CORE - Weight Configuration (scoring/weights.py)
================================================================================
Sistema de pesos ajustáveis para o scoring system.

ATENÇÃO: Ajuste esses valores com MUITO cuidado!
- Valores muito altos → Falsos positivos (bloqueia tráfego legítimo)
- Valores muito baixos → Falsos negativos (deixa ataques passarem)

Recomendação: Faça ajustes incrementais de 0.1 e teste bastante.
================================================================================
"""

from typing import Dict, List
from dataclasses import dataclass

from typing import TYPE_CHECKING


@dataclass
class WeightConfig:
    """
    Configuração centralizada de pesos para o sistema de scoring.
    
    Estrutura hierárquica:
    1. Dimension Weights (pesos das dimensões principais)
    2. Factor Weights (pesos dos fatores individuais)
    3. Bonuses/Penalties (ajustes contextuais)
    """
    
    # ========================================================================
    #                    PESOS DAS DIMENSÕES PRINCIPAIS
    # ========================================================================
    # Esses pesos multiplicam o score de cada dimensão no cálculo final
    
    dimension_weights: Dict[str, float] = None
    
    def __post_init__(self):
        if self.dimension_weights is None:
            self.dimension_weights = {
                'ip_reputation': 1.0,      # IP é CRÍTICO (peso máximo)
                'behavior': 0.8,            # Comportamento é MUITO importante
                'payload': 0.9,             # Conteúdo é CRÍTICO
                'temporal': 0.4,            # Horário é SECUNDÁRIO
                'fingerprint': 0.5,         # Headers/UA são MODERADOS
            }
    
    # ========================================================================
    #                    FATORES DE REPUTAÇÃO DE IP
    # ========================================================================
    
    IP_BLACKLISTED = 2.0        # IP em blacklist conhecida → BLOQUEIO QUASE CERTO
    IP_UNKNOWN = 0.2            # IP nunca visto antes → SUSPEITA LEVE
    IP_TOR_PROXY = 1.0          # Tor/VPN/Proxy → SUSPEITA MODERADA
    IP_GEO_RISK_HIGH = 0.5      # País de alto risco (CN, RU, KP) → SUSPEITA MODERADA
    IP_GEO_RISK_MEDIUM = 0.1    # País de risco médio → SUSPEITA LEVE
    IP_RECENT_ATTACK = 0.7      # IP atacou recentemente → SUSPEITA ALTA
    
    # ========================================================================
    #                    FATORES DE COMPORTAMENTO
    # ========================================================================
    
    # Taxa de requisições (requests/min)
    RATE_LOW = 0.0              # < 10 req/min → Normal
    RATE_MEDIUM = 0.5           # 10-50 req/min → Suspeita leve
    RATE_HIGH = 1.0             # > 50 req/min → Provável scan/DoS
    
    # Diversidade de portas
    PORT_DIVERSITY_LOW = 0.0    # 1-3 portas → Normal
    PORT_DIVERSITY_MEDIUM = 0.5 # 4-10 portas → Suspeita moderada
    PORT_DIVERSITY_HIGH = 1.0   # 10+ portas → Provável scan
    
    # Sequencialidade (portas 80, 81, 82... típico de Nmap)
    SEQUENTIAL_SCAN = 0.5       # Acesso sequencial → Típico de scanner
    
    # Múltiplas falhas
    MULTIPLE_FAILURES = 0.6     # Várias tentativas falhadas → Brute force
    
    # ========================================================================
    #                    FATORES DE PAYLOAD
    # ========================================================================
    
    SQL_INJECTION = 1.5         # SQL injection detectado → ATAQUE CERTO
    XSS_ATTEMPT = 1.2           # XSS detectado → ATAQUE CERTO
    PATH_TRAVERSAL = 1.3        # Path traversal (../..) → ATAQUE CERTO
    COMMAND_INJECTION = 1.4     # Command injection → ATAQUE CERTO
    
    # Tamanho anormal do payload
    PAYLOAD_TOO_LARGE = 0.4     # Payload > 10KB → Suspeita leve
    PAYLOAD_TOO_SMALL = 0.2     # Payload < 10 bytes → Suspeita leve
    
    # Encoding suspeito
    SUSPICIOUS_ENCODING = 0.3   # Base64, URL encode múltiplo → Suspeita leve
    
    # ========================================================================
    #                    FATORES TEMPORAIS
    # ========================================================================
    
    SUSPICIOUS_HOUR = 0.3       # Acesso em horário incomum (0h-6h) → Suspeita leve
    WEEKEND_ACCESS = 0.2        # Acesso em fim de semana → Suspeita leve
    BURST_TRAFFIC = 0.5         # Pico súbito de tráfego → Suspeita moderada
    
    # ========================================================================
    #                    FATORES DE FINGERPRINTING
    # ========================================================================
    
    SCANNER_USER_AGENT = 0.6    # User-Agent de scanner conhecido → Suspeita alta
    EMPTY_USER_AGENT = 0.4      # User-Agent vazio → Suspeita moderada
    MISSING_HEADERS = 0.3       # Headers HTTP essenciais ausentes → Suspeita leve
    SUSPICIOUS_REFERER = 0.2    # Referer suspeito → Suspeita leve
    
    # ========================================================================
    #                    BÔNUS (Agravam o score)
    # ========================================================================
    
    BONUS_EXPLOIT_ATTEMPT = 1.0         # Tentativa de explorar CVE conhecida
    BONUS_MULTIPLE_TECHNIQUES = 0.5     # Usa múltiplas técnicas de ataque
    BONUS_KNOWN_MALWARE_SIGNATURE = 1.5 # Assinatura de malware conhecida
    BONUS_REPEATED_OFFENDER = 0.8       # IP já bloqueado antes
    
    # ========================================================================
    #                    PENALIDADES (Atenuam o score)
    # ========================================================================
    
    PENALTY_WHITELIST = -2.0            # IP em whitelist → Quase zera score
    PENALTY_VALID_TOKEN = -1.0          # Token/API key válido → Confiável
    PENALTY_HTTPS_VALID = -0.2          # HTTPS com certificado válido → Mais confiável
    PENALTY_KNOWN_BOT = -0.5            # Bot conhecido (Googlebot) → Legítimo
    
    # ========================================================================
    #                    THRESHOLDS DE DECISÃO
    # ========================================================================
    
    THRESHOLD_SAFE = 0.0            # < 0.0 → ALLOW (confiável)
    THRESHOLD_LOW = 0.3             # 0.0 - 0.3 → ALLOW (baixo risco)
    THRESHOLD_MEDIUM = 0.7          # 0.3 - 0.7 → MONITOR (risco médio)
    THRESHOLD_HIGH = 1.0            # 0.7 - 1.0 → ENCRYPT/REDIRECT (risco alto)
    THRESHOLD_CRITICAL = 1.5        # 1.0 - 1.5 → RATE_LIMIT (crítico)
    THRESHOLD_MALICIOUS = 2.0       # > 1.5 → BLOCK (malicioso)
    
    # ========================================================================
    #                    LISTAS DE REFERÊNCIA
    # ========================================================================
    
    # User-Agents conhecidos de scanners
    SCANNER_USER_AGENTS = [
        "nmap",
        "masscan",
        "zap",
        "nikto",
        "sqlmap",
        "metasploit",
        "burp",
        "python-requests",
        "curl",
        "wget",
    ]
    
    # Países de alto risco (ajuste conforme seu contexto)
    HIGH_RISK_COUNTRIES = [
        "CN",  # China
        "RU",  # Rússia
        "KP",  # Coreia do Norte
        "IR",  # Irã
    ]
    
    # Países de risco médio
    MEDIUM_RISK_COUNTRIES = [
        "VN",  # Vietnã
        "IN",  # Índia (devido ao volume de tráfego)
        "BR",  # Brasil (devido a botnets)
    ]
    
    # Portas de alto risco (comumente exploradas)
    HIGH_RISK_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
    ]
    
    def get_dimension_weight(self, dimension: str) -> float:
        """Retorna o peso de uma dimensão específica"""
        return self.dimension_weights.get(dimension, 0.0)
    
    def update_dimension_weight(self, dimension: str, new_weight: float):
        """Atualiza o peso de uma dimensão (para tuning dinâmico)"""
        if dimension in self.dimension_weights:
            self.dimension_weights[dimension] = max(0.0, min(2.0, new_weight))
    
    def is_scanner_user_agent(self, user_agent: str) -> bool:
        """Verifica se o User-Agent é de um scanner conhecido"""
        if not user_agent:
            return False
        ua_lower = user_agent.lower()
        return any(scanner in ua_lower for scanner in self.SCANNER_USER_AGENTS)
    
    def get_geo_risk(self, country_code: str) -> float:
        """Retorna o score de risco geográfico"""
        if not country_code:
            return 0.0
        if country_code in self.HIGH_RISK_COUNTRIES:
            return self.IP_GEO_RISK_HIGH
        if country_code in self.MEDIUM_RISK_COUNTRIES:
            return self.IP_GEO_RISK_MEDIUM
        return 0.0
    
    def is_high_risk_port(self, port: int) -> bool:
        """Verifica se a porta é considerada de alto risco"""
        return port in self.HIGH_RISK_PORTS


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    config = WeightConfig()
    
    print("=" * 80)
    print("UMBRA CORE - Configuração de Pesos")
    print("=" * 80)
    print()
    
    print(" Pesos das Dimensões:")
    for dim, weight in config.dimension_weights.items():
        print(f"  • {dim:20s}: {weight:.1f}")
    print()
    
    print(" Fatores de IP:")
    print(f"  • Blacklisted: {config.IP_BLACKLISTED}")
    print(f"  • Unknown: {config.IP_UNKNOWN}")
    print(f"  • Tor/Proxy: {config.IP_TOR_PROXY}")
    print()
    
    print(" Fatores de Comportamento:")
    print(f"  • High Rate: {config.RATE_HIGH}")
    print(f"  • Sequential Scan: {config.SEQUENTIAL_SCAN}")
    print()
    
    print(" Fatores de Payload:")
    print(f"  • SQL Injection: {config.SQL_INJECTION}")
    print(f"  • XSS: {config.XSS_ATTEMPT}")
    print(f"  • Path Traversal: {config.PATH_TRAVERSAL}")
    print()

    print(" Thresholds de Decisão:")
    print(f"  • Safe: < {config.THRESHOLD_SAFE}")
    print(f"  • Low: {config.THRESHOLD_SAFE} - {config.THRESHOLD_LOW}")
    print(f"  • Medium: {config.THRESHOLD_LOW} - {config.THRESHOLD_MEDIUM}")
    print(f"  • High: {config.THRESHOLD_MEDIUM} - {config.THRESHOLD_HIGH}")
    print(f"  • Critical: {config.THRESHOLD_HIGH} - {config.THRESHOLD_CRITICAL}")
    print(f"  • Malicious: > {config.THRESHOLD_CRITICAL}")
    print()
    
    print("🧪 Testes:")
    print(f"  • 'nmap' é scanner? {config.is_scanner_user_agent('nmap scripting engine')}")
    print(f"  • Risco geo CN: {config.get_geo_risk('CN')}")
    print(f"  • Porta 3306 é de risco? {config.is_high_risk_port(3306)}")
