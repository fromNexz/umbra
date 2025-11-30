"""
================================================================================
                    UMBRA CORE - Script de Teste Completo
================================================================================
Testa todos os componentes do Umbra Core de forma integrada.

Uso:
    python test_umbra_core.py

Esse script:
1. Cria eventos de teste (normais e maliciosos)
2. Processa cada evento pelo sistema completo
3. Exibe os resultados de forma organizada
4. Mostra estatísticas finais
================================================================================
"""

import sys
import time
from pathlib import Path

# Adiciona o diretório pai ao path para importar umbra_core
sys.path.insert(0, str(Path(__file__).parent.parent))

# Importa componentes do Umbra Core
try:
    from umbra_core.config import UmbraConfig
    from umbra_core.models.event import Event, EventType
    from umbra_core.scoring.weights import WeightConfig
    from umbra_core.scoring.factors import ScoringFactors
    from umbra_core.scoring.engine import ScoringEngine
    from umbra_core.decision.policy import PolicyEngine
    from umbra_core.storage.event_logger import EventLogger
except ImportError as e:
    print(f"❌ Erro ao importar módulos do Umbra Core: {e}")
    print("\nVerifique se:")
    print("  1. Todos os arquivos foram criados corretamente")
    print("  2. Os __init__.py estão presentes em cada diretório")
    print("  3. Você está executando do diretório correto")
    sys.exit(1)


class UmbraCoreTester:
    """Classe para testar o Umbra Core completo"""
    
    def __init__(self):
        """Inicializa todos os componentes"""
        print("🚀 Inicializando Umbra Core...")
        
        # Configuração
        self.config_global = UmbraConfig
        self.weight_config = WeightConfig()
        
        # Componentes
        self.scoring_factors = ScoringFactors(self.weight_config)
        self.scoring_engine = ScoringEngine(self.weight_config, self.scoring_factors)
        self.policy_engine = PolicyEngine(self.weight_config)
        self.event_logger = EventLogger(
            log_dir="test_logs",
            enable_console=False  # Desabilita para não poluir output
        )
        
        print("✅ Umbra Core inicializado com sucesso!")
        print()
    
    def create_test_events(self):
        """Cria eventos de teste variados"""
        events = []
        
        # 1. Evento NORMAL - Requisição legítima
        events.append({
            'name': '✅ Requisição Legítima',
            'event': Event(
                event_type=EventType.HTTP_REQUEST,
                source_ip="192.168.1.50",
                source_country="BR",
                target_ip="192.168.1.1",
                target_port=80,
                target_service="http",
                request_rate=2.0,
                payload_size=150,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                http_headers={"Host": "example.com", "Accept": "*/*"},
            )
        })
        
        # 2. Evento SUSPEITO - Muitas requisições
        events.append({
            'name': '⚠️  Alta Taxa de Requisições',
            'event': Event(
                event_type=EventType.HTTP_REQUEST,
                source_ip="203.0.113.45",
                target_ip="192.168.1.1",
                target_port=80,
                request_rate=60.0,  # 60 req/min é muito
                payload_size=200,
                user_agent="Mozilla/5.0",
            )
        })
        
        # 3. Evento MALICIOSO - Port Scan (típico de Nmap)
        events.append({
            'name': '🚨 Port Scan Detectado',
            'event': Event(
                event_type=EventType.NETWORK_SCAN,
                source_ip="198.51.100.23",
                source_country="CN",
                target_ip="192.168.1.1",
                ports_scanned=[21, 22, 23, 80, 443, 3306, 8080, 5432, 6379],
                sequential_access=True,
                request_rate=150.0,
                user_agent="nmap scripting engine",
            )
        })
        
        # 4. Evento CRÍTICO - SQL Injection
        events.append({
            'name': '💀 SQL Injection',
            'event': Event(
                event_type=EventType.HTTP_REQUEST,
                source_ip="203.0.113.99",
                source_country="RU",
                target_ip="192.168.1.10",
                target_port=80,
                payload_sample="?id=1' UNION SELECT username,password FROM users--",
                payload_size=512,
                contains_sql_injection=True,
                request_rate=5.0,
                user_agent="sqlmap/1.4",
            )
        })
        
        # 5. Evento MALICIOSO - XSS + Path Traversal
        events.append({
            'name': '🔥 Múltiplos Ataques',
            'event': Event(
                event_type=EventType.HTTP_REQUEST,
                source_ip="198.51.100.45",
                target_ip="192.168.1.10",
                target_port=443,
                payload_sample="<script>alert('XSS')</script>../../etc/passwd",
                payload_size=1024,
                contains_xss=True,
                contains_path_traversal=True,
                request_rate=20.0,
                hour_of_day=3,  # 3h da manhã
                user_agent="",
            )
        })
        
        # 6. Evento SEGURO - IP Whitelisted
        self.scoring_factors.ip_whitelist.add("192.168.1.100")
        events.append({
            'name': '✨ IP Whitelisted',
            'event': Event(
                event_type=EventType.API_CALL,
                source_ip="192.168.1.100",
                target_ip="192.168.1.1",
                target_port=8080,
                request_rate=100.0,  # Mesmo com alta taxa
                metadata={'valid_token': True}
            )
        })
        
        return events
    
    def process_event(self, event, event_name):
        """Processa um evento completo"""
        print("=" * 80)
        print(f"{event_name}")
        print("=" * 80)
        
        # Informações do evento
        print(f"📍 Origem: {event.source_ip} ({event.source_country or 'N/A'})")
        print(f"🎯 Destino: {event.target_ip}:{event.target_port or 'N/A'}")
        print(f"📊 Taxa: {event.request_rate:.1f} req/min")
        if event.ports_scanned:
            print(f"🔍 Portas: {len(event.ports_scanned)} escaneadas")
        if event.payload_sample:
            print(f"💬 Payload: {event.payload_sample[:50]}...")
        print()
        
        # ETAPA 1: Scoring
        start_time = time.perf_counter()
        scoring_result = self.scoring_engine.calculate_score(event)
        scoring_time = (time.perf_counter() - start_time) * 1000
        
        print(f"📊 SCORE FINAL: {scoring_result.final_score:.3f}")
        print(f"⚠️  SEVERIDADE: {scoring_result.severity.upper()}")
        print(f"⏱️  Processamento: {scoring_time:.2f}ms")
        print()
        
        # Mostra scores por dimensão
        print("📈 Scores por Dimensão:")
        for dim, score in scoring_result.dimension_scores.items():
            bar_length = int(score * 10)
            bar = "█" * bar_length
            print(f"   {dim:20s}: {score:5.2f} {bar}")
        print()
        
        # ETAPA 2: Decisão
        decision = self.policy_engine.make_decision(scoring_result)
        
        print(f"🎯 DECISÃO: {decision.action.value.upper()}")
        print(f"📝 Razão: {decision.reason}")
        if decision.recommended_duration_seconds:
            duration_hours = decision.recommended_duration_seconds / 3600
            print(f"⏰ Duração: {duration_hours:.1f}h")
        print()
        
        # ETAPA 3: Logging
        self.event_logger.log_event(event, scoring_result, decision)
        
        print()
        return scoring_result, decision
    
    def run_tests(self):
        """Executa todos os testes"""
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 20 + "UMBRA CORE - TESTE COMPLETO" + " " * 31 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        
        # Mostra configuração
        print("⚙️  CONFIGURAÇÃO:")
        print(f"   Sistema: {self.config_global.SYSTEM_NAME} v{self.config_global.VERSION}")
        print(f"   Logs: {self.config_global.LOG_DIR}")
        print(f"   Cache: {'Habilitado' if self.config_global.ENABLE_SCORE_CACHE else 'Desabilitado'}")
        print()
        
        # Cria eventos de teste
        test_events = self.create_test_events()
        
        print(f"🧪 Testando {len(test_events)} cenários...")
        print()
        
        # Processa cada evento
        results = []
        for test_case in test_events:
            scoring_result, decision = self.process_event(
                test_case['event'],
                test_case['name']
            )
            results.append({
                'name': test_case['name'],
                'score': scoring_result.final_score,
                'severity': scoring_result.severity,
                'action': decision.action.value,
            })
            time.sleep(0.5)  # Pequena pausa para legibilidade
        
        # Mostra resumo
        self.show_summary(results)
    
    def show_summary(self, results):
        """Mostra resumo dos testes"""
        print()
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 30 + "RESUMO DOS TESTES" + " " * 32 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        
        # Tabela de resultados
        print("📋 Resultados:")
        print(f"{'Teste':<30} {'Score':>8} {'Severidade':>12} {'Ação':>15}")
        print("-" * 70)
        for result in results:
            print(f"{result['name']:<30} {result['score']:>8.2f} {result['severity']:>12} {result['action']:>15}")
        print()
        
        # Estatísticas do engine
        print("📊 Estatísticas do Scoring Engine:")
        engine_stats = self.scoring_engine.get_stats()
        for key, value in engine_stats.items():
            print(f"   • {key}: {value}")
        print()
        
        # Estatísticas de decisões
        print("⚖️  Estatísticas de Decisões:")
        policy_stats = self.policy_engine.get_stats()
        for key, value in policy_stats.items():
            if isinstance(value, dict):
                print(f"   {key}:")
                for k, v in value.items():
                    print(f"      • {k}: {v}")
            else:
                print(f"   • {key}: {value}")
        print()
        
        # Estatísticas do logger
        print("📁 Estatísticas de Logging:")
        logger_stats = self.event_logger.get_stats()
        for key, value in logger_stats.items():
            if isinstance(value, dict):
                print(f"   {key}:")
                for k, v in value.items():
                    print(f"      • {k}: {v}")
            else:
                print(f"   • {key}: {value}")
        print()
        
        print("✅ TESTES CONCLUÍDOS COM SUCESSO!")
        print()


# ============================================================================
#                          EXECUÇÃO PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    try:
        tester = UmbraCoreTester()
        tester.run_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️  Teste interrompido pelo usuário.")
    except Exception as e:
        print(f"\n❌ ERRO durante os testes: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)