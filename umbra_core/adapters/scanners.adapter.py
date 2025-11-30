"""
================================================================================
            UMBRA CORE - Scanner Adapter (adapters/scanner_adapter.py)
================================================================================
Converte resultados do Umbra Scanners em Events do Umbra Core.
Ponte entre os sistemas de reconhecimento e o sistema de decisão.
================================================================================
"""

import json
from typing import Dict, Any, List
from pathlib import Path

from umbra_core.models.event import Event, EventType


class ScannerAdapter:
    """
    Adaptador que converte resultados dos scanners em Events.
    
    Workflow:
    1. Recebe JSON do scanner (recon, scan, enum)
    2. Extrai informações relevantes
    3. Cria um Event padronizado
    4. Retorna para o Umbra Core processar
    """
    
    @staticmethod
    def from_port_scan(scan_result: Dict[str, Any]) -> Event:
        """
        Converte resultado de port scan em Event.
        
        Args:
            scan_result: Dict do resultado do scan (do active_scan.py)
            
        Returns:
            Event pronto para scoring
        """
        target_ip = scan_result.get('target_ip')
        results = scan_result.get('results', [])
        meta = scan_result.get('meta', {})
        
        # Extrai portas escaneadas
        ports_scanned = [r['port'] for r in results]
        
        # Detecta acesso sequencial
        sequential = ScannerAdapter._is_sequential_scan(ports_scanned)
        
        # Calcula taxa de requisições
        scan_time = meta.get('scan_time_s', 1)
        ports_count = meta.get('ports_scanned', len(ports_scanned))
        request_rate = (ports_count / scan_time) * 60  # req/min
        
        # Identifica serviços sensíveis
        sensitive_services = ['ssh', 'mysql', 'postgresql', 'redis', 'mongodb']
        has_sensitive = any(
            r.get('service') in sensitive_services 
            for r in results
        )
        
        # Cria evento
        event = Event(
            event_type=EventType.NETWORK_SCAN,
            source_ip=target_ip,  # No scan, source é o alvo
            target_ip=target_ip,
            ports_scanned=ports_scanned,
            sequential_access=sequential,
            request_rate=request_rate,
            metadata={
                'scanner_type': 'umbra_active_scan',
                'ports_open': meta.get('ports_open', 0),
                'ports_filtered': meta.get('ports_filtered', 0),
                'has_sensitive_services': has_sensitive,
                'scan_result': scan_result,  # Preserva resultado completo
            }
        )
        
        return event
    
    @staticmethod
    def from_passive_recon(recon_result: Dict[str, Any]) -> Event:
        """
        Converte resultado de recon passivo em Event.
        
        Args:
            recon_result: Dict do resultado do recon (do passive_osint.py)
            
        Returns:
            Event pronto para scoring
        """
        target = recon_result.get('target')
        target_ip = recon_result.get('results', {}).get('resolved_ip') or target
        results = recon_result.get('results', {})
        
        # Extrai subdomínios
        subdomains = results.get('subdomains', [])
        
        # ASN info
        asn_data = results.get('asn', {})
        country = asn_data.get('country')
        
        # Cria evento
        event = Event(
            event_type=EventType.DNS_QUERY,
            source_ip=target_ip,
            target_ip=target_ip,
            source_country=country,
            metadata={
                'recon_type': 'umbra_passive_osint',
                'subdomains_count': len(subdomains),
                'has_whois': bool(results.get('whois')),
                'has_asn': bool(asn_data),
                'recon_result': recon_result,  # Preserva resultado completo
            }
        )
        
        return event
    
    @staticmethod
    def from_http_enum(enum_result: Dict[str, Any]) -> Event:
        """
        Converte resultado de HTTP enumeration em Event.
        
        Args:
            enum_result: Dict do resultado do enum (futuro)
            
        Returns:
            Event pronto para scoring
        """
        # + Implementar quando o módulo enum estiver pronto
        
        url = enum_result.get('url')
        findings = enum_result.get('findings', [])
        
        event = Event(
            event_type=EventType.HTTP_REQUEST,
            metadata={
                'enum_type': 'umbra_http_enum',
                'url': url,
                'findings_count': len(findings),
                'enum_result': enum_result,
            }
        )
        
        return event
    
    @staticmethod
    def from_json_file(filepath: str) -> Event:
        """
        Lê resultado de JSON e converte em Event.
        
        Args:
            filepath: Caminho do arquivo JSON do scanner
            
        Returns:
            Event pronto para scoring
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Detecta tipo de scan baseado no JSON
        scan_type = data.get('type', '')
        
        if 'active_scan' in scan_type or 'port_scan' in scan_type:
            return ScannerAdapter.from_port_scan(data)
        
        elif 'passive' in scan_type or 'recon' in scan_type:
            return ScannerAdapter.from_passive_recon(data)
        
        elif 'http_enum' in scan_type:
            return ScannerAdapter.from_http_enum(data)
        
        else:
            raise ValueError(f"Tipo de scan desconhecido: {scan_type}")
    
    @staticmethod
    def _is_sequential_scan(ports: List[int]) -> bool:
        """Detecta se portas foram escaneadas sequencialmente."""
        if len(ports) < 3:
            return False
        
        sorted_ports = sorted(ports)
        sequential_count = 0
        
        for i in range(len(sorted_ports) - 1):
            if sorted_ports[i+1] - sorted_ports[i] == 1:
                sequential_count += 1
        
        return sequential_count / len(sorted_ports) > 0.5


# ============================================================================
#                          PIPELINE COMPLETO
# ============================================================================

class ScannerPipeline:
    """
    Pipeline completo: Scanner → Adapter → Core → Decision
    """
    
    def __init__(self, umbra_core):
        """
        Args:
            umbra_core: Instância configurada do Umbra Core
        """
        self.core = umbra_core
        self.adapter = ScannerAdapter()
    
    def process_scan_result(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processa resultado de scan completo.
        
        Args:
            scan_result: Dict do resultado do scanner
            
        Returns:
            Dict com Event, ScoringResult e Decision
        """
        # 1. Converte para Event
        event = self.adapter.from_port_scan(scan_result)
        
        # 2. Calcula score
        scoring_result = self.core.scoring_engine.calculate_score(event)
        
        # 3. Toma decisão
        decision = self.core.policy_engine.make_decision(scoring_result)
        
        # 4. Loga tudo
        self.core.event_logger.log_event(event, scoring_result, decision)
        
        # 5. Retorna resultado completo
        return {
            'event': event.to_dict(),
            'scoring': scoring_result.to_dict(),
            'decision': decision.to_dict(),
        }
    
    def process_scan_file(self, filepath: str) -> Dict[str, Any]:
        """
        Processa arquivo JSON de scan.
        
        Args:
            filepath: Caminho do arquivo
            
        Returns:
            Resultado completo do pipeline
        """
        event = self.adapter.from_json_file(filepath)
        
        scoring_result = self.core.scoring_engine.calculate_score(event)
        decision = self.core.policy_engine.make_decision(scoring_result)
        
        self.core.event_logger.log_event(event, scoring_result, decision)
        
        return {
            'event': event.to_dict(),
            'scoring': scoring_result.to_dict(),
            'decision': decision.to_dict(),
        }


# ============================================================================
#                          EXEMPLO DE USO
# ============================================================================

if __name__ == "__main__":
    import sys
    from pathlib import Path
    
    # Adiciona umbra_core ao path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from umbra_core.scoring.weights import WeightConfig
    from umbra_core.scoring.factors import ScoringFactors
    from umbra_core.scoring.engine import ScoringEngine
    from umbra_core.decision.policy import PolicyEngine
    from umbra_core.storage.event_logger import EventLogger
    
    print("=" * 80)
    print("TESTE: Scanner Adapter")
    print("=" * 80)
    print()
    
    # Simula resultado de port scan
    mock_scan_result = {
        'target': 'localhost',
        'target_ip': '127.0.0.1',
        'type': 'recon/active_scan',
        'results': [
            {'port': 22, 'service': 'ssh', 'banner': 'OpenSSH_8.2'},
            {'port': 80, 'service': 'http', 'banner': 'nginx/1.18.0'},
            {'port': 3306, 'service': 'mysql', 'banner': 'MySQL 5.7'},
        ],
        'meta': {
            'scan_time_s': 2.5,
            'ports_scanned': 100,
            'ports_open': 3,
            'ports_filtered': 0,
        }
    }
    
    # Converte para Event
    adapter = ScannerAdapter()
    event = adapter.from_port_scan(mock_scan_result)
    
    print("Scan Result convertido em Event:")
    print(f"   Event ID: {event.event_id}")
    print(f"   Type: {event.event_type.value}")
    print(f"   Source IP: {event.source_ip}")
    print(f"   Portas: {event.ports_scanned}")
    print(f"   Request Rate: {event.request_rate:.1f} req/min")
    print(f"   Sequential: {event.sequential_access}")
    print()
    
    # Agora processa no Umbra Core
    print("🔍 Processando no Umbra Core...")
    
    config = WeightConfig()
    factors = ScoringFactors(config)
    engine = ScoringEngine(config, factors)
    policy = PolicyEngine(config)
    
    scoring_result = engine.calculate_score(event)
    decision = policy.make_decision(scoring_result)
    
    print(f"   Score: {scoring_result.final_score:.2f}")
    print(f"   Severidade: {scoring_result.severity}")
    print(f"   Decisão: {decision.action.value}")
    print(f"   Razão: {decision.reason}")
    print()
    
    print("Pipeline completo funcionando!")
