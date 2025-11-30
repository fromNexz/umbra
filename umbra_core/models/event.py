"""
================================================================================
                    UMBRA CORE - Event Model (models/event.py)
================================================================================
Modelo padronizado de eventos para análise de segurança.
Todos os eventos processados pelo Umbra Core seguem este formato.
================================================================================
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class EventType(Enum):
    """Tipos de eventos suportados pelo sistema"""
    NETWORK_SCAN = "network_scan"      # Port scan, host discovery
    HTTP_REQUEST = "http_request"      # Requisições HTTP/HTTPS
    AUTH_ATTEMPT = "auth_attempt"      # Tentativas de autenticação
    FILE_ACCESS = "file_access"        # Acesso a arquivos
    API_CALL = "api_call"              # Chamadas de API
    DNS_QUERY = "dns_query"            # Consultas DNS
    UNKNOWN = "unknown"                # Tipo desconhecido


class Severity(Enum):
    """Níveis de severidade baseados no score calculado"""
    SAFE = "safe"           # Score < 0.0 (confiável) OK
    LOW = "low"             # Score 0.0 - 0.3 (baixo risco) low
    MEDIUM = "medium"       # Score 0.3 - 0.7 (risco médio) medium 
    HIGH = "high"           # Score 0.7 - 1.0 (risco alto) high
    CRITICAL = "critical"   # Score 1.0 - 1.5 (crítico) critical
    MALICIOUS = "malicious" # Score > 1.5 (malicioso) malicious


@dataclass
class Event:
    """
    Modelo padrão de evento para análise de segurança.
    
    Attributes:
        event_id: Identificador único do evento (UUID)
        timestamp: Timestamp Unix do evento
        event_type: Tipo do evento (enum EventType)
        
        source_ip: IP de origem
        source_port: Porta de origem (opcional)
        source_country: País de origem (ISO code, opcional)
        
        target_ip: IP de destino
        target_port: Porta de destino (opcional)
        target_service: Serviço alvo (http, ssh, mysql, etc)
        
        request_rate: Taxa de requisições por minuto
        ports_scanned: Lista de portas acessadas/escaneadas
        sequential_access: Se as portas foram acessadas sequencialmente
        
        payload_size: Tamanho do payload em bytes
        payload_sample: Amostra do payload (primeiros 1000 chars)
        contains_sql_injection: Flag de detecção de SQL injection
        contains_xss: Flag de detecção de XSS
        contains_path_traversal: Flag de detecção de path traversal
        
        user_agent: User-Agent HTTP (opcional)
        http_headers: Headers HTTP completos
        
        hour_of_day: Hora do dia (0-23)
        is_weekend: Se ocorreu em fim de semana
        
        metadata: Dados adicionais customizados
    """
    
    # ========== Identificação ==========
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: EventType = EventType.UNKNOWN
    
    # ========== Origem ==========
    source_ip: str = ""
    source_port: Optional[int] = None
    source_country: Optional[str] = None
    
    # ========== Destino ==========
    target_ip: str = ""
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    
    # ========== Comportamento ==========
    request_rate: float = 0.0  # Requisições por minuto
    ports_scanned: List[int] = field(default_factory=list)
    sequential_access: bool = False
    
    # ========== Payload ==========
    payload_size: int = 0
    payload_sample: str = ""
    contains_sql_injection: bool = False
    contains_xss: bool = False
    contains_path_traversal: bool = False
    
    # ========== Fingerprinting ==========
    user_agent: Optional[str] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    
    # ========== Contexto Temporal ==========
    hour_of_day: int = field(default_factory=lambda: datetime.now().hour)
    is_weekend: bool = field(default_factory=lambda: datetime.now().weekday() >= 5)
    
    # ========== Metadados ==========
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte o evento para dicionário JSON-serializável.
        
        Returns:
            Dict com todos os dados do evento
        """
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data
    
    def to_json(self) -> str:
        """
        Converte o evento para string JSON.
        
        Returns:
            String JSON formatada
        """
        import json
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """
        Cria um evento a partir de um dicionário.
        
        Args:
            data: Dicionário com dados do evento
            
        Returns:
            Instância de Event
        """
        # Converte event_type de string para enum
        if 'event_type' in data and isinstance(data['event_type'], str):
            data['event_type'] = EventType(data['event_type'])
        
        return cls(**data)
    
    def __repr__(self) -> str:
        """Representação legível do evento"""
        return (
            f"Event(id={self.event_id[:8]}..., "
            f"type={self.event_type.value}, "
            f"source={self.source_ip}:{self.source_port or 'N/A'}, "
            f"target={self.target_ip}:{self.target_port or 'N/A'})"
        )


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    # Exemplo 1: Evento de port scan (típico de Nmap)
    scan_event = Event(
        event_type=EventType.NETWORK_SCAN,
        source_ip="192.168.1.100",
        target_ip="192.168.1.1",
        ports_scanned=[21, 22, 23, 80, 443, 3306, 8080],
        sequential_access=False,
        request_rate=120.0,  # 120 requisições por minuto
        metadata={"tool": "nmap", "scan_type": "syn_scan"}
    )
    
    print("Exemplo 1: Port Scan")
    print(scan_event)
    print()
    
    # Exemplo 2: Evento de SQL injection
    sqli_event = Event(
        event_type=EventType.HTTP_REQUEST,
        source_ip="203.0.113.45",
        source_country="CN",
        target_ip="192.168.1.10",
        target_port=80,
        target_service="http",
        payload_sample="?id=1' OR '1'='1",
        payload_size=256,
        contains_sql_injection=True,
        user_agent="Mozilla/5.0 (compatible; MSIE 9.0)",
        http_headers={"Host": "example.com", "Accept": "*/*"},
        request_rate=5.0
    )
    
    print("Exemplo 2: SQL Injection")
    print(sqli_event)
    print()
    
    # Exemplo 3: Acesso suspeito em horário incomum
    suspicious_event = Event(
        event_type=EventType.AUTH_ATTEMPT,
        source_ip="198.51.100.23",
        target_ip="192.168.1.50",
        target_port=22,
        target_service="ssh",
        hour_of_day=3,  # 3h da manhã
        is_weekend=True,
        request_rate=10.0,
        metadata={"failed_attempts": 5}
    )
    
    print("Exemplo 3: Acesso Suspeito")
    print(suspicious_event)
    print()
    
    # Exemplo 4: Conversão para JSON
    print("Exemplo 4: Evento em JSON")
    print(scan_event.to_json())