"""
================================================================================
                UMBRA CORE - Event Logger (storage/event_logger.py)
================================================================================
Sistema de logging estruturado para eventos de segurança.
Registra todos os eventos, scores e decisões para análise posterior.
================================================================================
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from logging.handlers import RotatingFileHandler


class EventLogger:
    """
    Logger especializado para eventos de segurança.
    
    Features:
    - Logs estruturados em JSON
    - Rotação automática de arquivos
    - Níveis de log baseados em severidade
    - Correlação via trace_id
    - Suporte a múltiplos outputs (arquivo, console, futuro: DB)
    """
    
    def __init__(
        self,
        log_dir: str = "logs",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        enable_console: bool = True
    ):
        """
        Args:
            log_dir: Diretório para salvar logs
            max_bytes: Tamanho máximo de cada arquivo de log
            backup_count: Número de backups a manter
            enable_console: Se True, também loga no console
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Cria loggers separados por tipo
        self.event_logger = self._setup_logger(
            'umbra.events',
            self.log_dir / 'events.log',
            max_bytes,
            backup_count
        )
        
        self.decision_logger = self._setup_logger(
            'umbra.decisions',
            self.log_dir / 'decisions.log',
            max_bytes,
            backup_count
        )
        
        self.security_logger = self._setup_logger(
            'umbra.security',
            self.log_dir / 'security.log',
            max_bytes,
            backup_count
        )
        
        # Console output (opcional)
        self.enable_console = enable_console
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            self.event_logger.addHandler(console_handler)
            self.decision_logger.addHandler(console_handler)
            self.security_logger.addHandler(console_handler)
        
        # Estatísticas
        self.stats = {
            'total_events_logged': 0,
            'events_by_severity': {},
            'decisions_by_action': {},
            'start_time': time.time(),
        }
    
    def _setup_logger(
        self,
        name: str,
        log_file: Path,
        max_bytes: int,
        backup_count: int
    ) -> logging.Logger:
        """Configura um logger com rotação de arquivos"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # Remove handlers existentes (evita duplicação)
        logger.handlers.clear()
        
        # Handler com rotação
        handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # Formato JSON estruturado
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        logger.propagate = False  # Não propaga para root logger
        
        return logger
    
    def log_event(self, event, scoring_result=None, decision=None):
        """
        Loga um evento completo com score e decisão.
        
        Args:
            event: Instância de Event
            scoring_result: Instância de ScoringResult (opcional)
            decision: Instância de Decision (opcional)
        """
        timestamp = datetime.now().isoformat()
        
        # Monta log estruturado
        log_entry = {
            'timestamp': timestamp,
            'event_id': event.event_id,
            'event_type': event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
            'source_ip': event.source_ip,
            'source_country': event.source_country,
            'target_ip': event.target_ip,
            'target_port': event.target_port,
            'target_service': event.target_service,
        }
        
        # Adiciona scoring se disponível
        if scoring_result:
            log_entry['score'] = {
                'final_score': round(scoring_result.final_score, 3),
                'severity': scoring_result.severity,
                'dimension_scores': {
                    k: round(v, 3) 
                    for k, v in scoring_result.dimension_scores.items()
                },
                'processing_time_ms': round(scoring_result.processing_time_ms, 2),
            }
            
            # Atualiza estatísticas
            severity = scoring_result.severity
            self.stats['events_by_severity'][severity] = \
                self.stats['events_by_severity'].get(severity, 0) + 1
        
        # Adiciona decisão se disponível
        if decision:
            log_entry['decision'] = {
                'action': decision.action.value if hasattr(decision.action, 'value') else str(decision.action),
                'reason': decision.reason,
                'duration_seconds': decision.recommended_duration_seconds,
            }
            
            # Atualiza estatísticas
            action = decision.action.value if hasattr(decision.action, 'value') else str(decision.action)
            self.stats['decisions_by_action'][action] = \
                self.stats['decisions_by_action'].get(action, 0) + 1
        
        # Escolhe nível de log baseado na severidade
        if scoring_result:
            severity = scoring_result.severity
            if severity in ['malicious', 'critical']:
                log_level = logging.CRITICAL
            elif severity == 'high':
                log_level = logging.ERROR
            elif severity == 'medium':
                log_level = logging.WARNING
            else:
                log_level = logging.INFO
        else:
            log_level = logging.INFO
        
        # Loga no arquivo de eventos
        self.event_logger.log(log_level, json.dumps(log_entry, ensure_ascii=False))
        
        # Se for evento de segurança crítico, loga também no security.log
        if scoring_result and scoring_result.severity in ['critical', 'malicious']:
            self.security_logger.critical(json.dumps(log_entry, ensure_ascii=False))
        
        # Atualiza contadores
        self.stats['total_events_logged'] += 1
    
    def log_decision(self, decision, event_id: str):
        """
        Loga apenas uma decisão (útil para rastreamento).
        
        Args:
            decision: Instância de Decision
            event_id: ID do evento relacionado
        """
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'event_id': event_id,
            'action': decision.action.value if hasattr(decision.action, 'value') else str(decision.action),
            'reason': decision.reason,
            'score': round(decision.score, 3),
            'severity': decision.severity,
            'duration_seconds': decision.recommended_duration_seconds,
            'metadata': decision.metadata,
        }
        
        # Nível de log baseado na ação
        if decision.action.value in ['block_perm', 'block_temp']:
            log_level = logging.ERROR
        elif decision.action.value in ['rate_limit', 'captcha']:
            log_level = logging.WARNING
        else:
            log_level = logging.INFO
        
        self.decision_logger.log(log_level, json.dumps(log_entry, ensure_ascii=False))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """
        Loga evento de segurança genérico.
        
        Args:
            event_type: Tipo do evento (ex: "ATTACK_BLOCKED", "IP_BLACKLISTED")
            details: Detalhes adicionais
        """
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'details': details,
        }
        
        self.security_logger.warning(json.dumps(log_entry, ensure_ascii=False))
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas de logging"""
        uptime_seconds = time.time() - self.stats['start_time']
        
        return {
            'total_events_logged': self.stats['total_events_logged'],
            'events_by_severity': self.stats['events_by_severity'],
            'decisions_by_action': self.stats['decisions_by_action'],
            'uptime_seconds': round(uptime_seconds, 2),
            'uptime_hours': round(uptime_seconds / 3600, 2),
            'log_directory': str(self.log_dir),
        }
    
    def search_logs(
        self,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100
    ) -> list:
        """
        Busca logs por critérios (implementação básica).
        
        Args:
            severity: Filtrar por severidade
            source_ip: Filtrar por IP de origem
            limit: Número máximo de resultados
            
        Returns:
            Lista de logs que correspondem aos critérios
        """
        results = []
        log_file = self.log_dir / 'events.log'
        
        if not log_file.exists():
            return results
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if len(results) >= limit:
                    break
                
                try:
                    entry = json.loads(line.strip())
                    
                    # Aplica filtros
                    if severity and entry.get('score', {}).get('severity') != severity:
                        continue
                    
                    if source_ip and entry.get('source_ip') != source_ip:
                        continue
                    
                    results.append(entry)
                
                except json.JSONDecodeError:
                    continue
        
        return results


# ============================================================================
#                          EXEMPLOS DE USO
# ============================================================================

if __name__ == "__main__":
    # Cria logger
    logger = EventLogger(log_dir="test_logs", enable_console=True)
    
    print("=" * 80)
    print("UMBRA CORE - Teste do Event Logger")
    print("=" * 80)
    print()
    
    # Simula eventos
    class MockEvent:
        event_id = "test-001"
        event_type = "network_scan"
        source_ip = "192.168.1.100"
        source_country = "BR"
        target_ip = "192.168.1.1"
        target_port = 80
        target_service = "http"
    
    class MockScoringResult:
        final_score = 1.5
        severity = "critical"
        dimension_scores = {
            'ip_reputation': 0.5,
            'behavior': 1.2,
            'payload': 0.8,
        }
        processing_time_ms = 2.5
    
    class MockDecision:
        class MockAction:
            value = "block_temp"
        action = MockAction()
        reason = "Atividade suspeita detectada"
        score = 1.5
        severity = "critical"
        recommended_duration_seconds = 3600
        metadata = {}
    
    # Loga evento completo
    print("📝 Logando evento...")
    logger.log_event(MockEvent(), MockScoringResult(), MockDecision())
    
    print("✅ Evento logado com sucesso!")
    print()
    
    # Mostra estatísticas
    print("📊 ESTATÍSTICAS:")
    stats = logger.get_stats()
    for key, value in stats.items():
        print(f"   • {key}: {value}")
    print()
    
    # Busca logs
    print("🔍 BUSCANDO LOGS (severity=critical):")
    results = logger.search_logs(severity="critical", limit=5)
    print(f"   Encontrados: {len(results)} resultados")
    if results:
        print(f"   Primeiro resultado:")
        print(f"   {json.dumps(results[0], indent=2, ensure_ascii=False)}")