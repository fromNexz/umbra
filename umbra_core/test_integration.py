"""
================================================================================
                TESTE DE INTEGRAÇÃO: Scanners + Core
================================================================================
Testa a integração completa entre Umbra Scanners e Umbra Core.

Workflow:
1. Roda scan (port scan ou recon)
2. Converte resultado em Event
3. Processa no Umbra Core (scoring + decision)
4. Exibe resultado
================================================================================
"""

import sys
import asyncio
from pathlib import Path

# Descobre o diretório atual
current_dir = Path(__file__).parent

# Adiciona ambos os sistemas ao path
# Ajuste esses caminhos conforme sua estrutura:
umbra_scanners_path = current_dir.parent / 'umbra_scanners'
umbra_core_path = current_dir

sys.path.insert(0, str(umbra_scanners_path))
sys.path.insert(0, str(umbra_core_path))

print(f"📁 Scanners path: {umbra_scanners_path}")
print(f"📁 Core path: {umbra_core_path}")
print()

# Importa scanners
try:
    from recon.active_scan import active_scan
    from recon.passive_osint import passive_recon
    print("✅ Scanners importados com sucesso")
except ImportError as e:
    print(f"❌ Erro ao importar scanners: {e}")
    print("\nVerifique se a estrutura está assim:")
    print("  Umbra/")
    print("  ├── umbra_scanners/")
    print("  │   └── recon/")
    print("  │       ├── active_scan.py")
    print("  │       └── passive_osint.py")
    print("  └── umbra_core/")
    print("      └── test_integration.py")
    sys.exit(1)

# Importa core
try:
    from umbra_core.scoring.weights import WeightConfig
    from umbra_core.scoring.factors import ScoringFactors
    from umbra_core.scoring.engine import ScoringEngine
    from umbra_core.decision.policy import PolicyEngine
    from umbra_core.storage.event_logger import EventLogger
    from umbra_core.adapters.scanner_adapter import ScannerAdapter
    print("✅ Umbra Core importado com sucesso")
except ImportError as e:
    print(f"❌ Erro ao importar Umbra Core: {e}")
    sys.exit(1)

print()


class UmbraIntegration:
    """Integração completa Scanners + Core"""
    
    def __init__(self):
        # Inicializa Core
        self.config = WeightConfig()
        self.factors = ScoringFactors(self.config)
        self.engine = ScoringEngine(self.config, self.factors)
        self.policy = PolicyEngine(self.config)
        self.logger = EventLogger(log_dir="integration_logs", enable_console=False)
        
        # Inicializa Adapter
        self.adapter = ScannerAdapter()
    
    async def test_port_scan_integration(self, target: str):
        """Testa integração com port scan"""
        print("=" * 80)
        print(f"🔍 PORT SCAN + UMBRA CORE: {target}")
        print("=" * 80)
        print()
        
        # 1. Roda scan
        print("1️⃣  Executando port scan...")
        scan_result = await active_scan(
            target=target,
            fast_mode=True,
            timeout=2,
            grab_banner=True
        )
        
        ports_open = scan_result['meta']['ports_open']
        print(f"   ✅ Scan completo: {ports_open} portas abertas")
        print()
        
        # 2. Converte para Event
        print("2️⃣  Convertendo para Event...")
        event = self.adapter.from_port_scan(scan_result)
        print(f"   ✅ Event criado: {event.event_id}")
        print(f"      Portas: {event.ports_scanned}")
        print(f"      Taxa: {event.request_rate:.1f} req/min")
        print()
        
        # 3. Calcula score
        print("3️⃣  Calculando score...")
        scoring_result = self.engine.calculate_score(event)
        print(f"   ✅ Score: {scoring_result.final_score:.3f}")
        print(f"      Severidade: {scoring_result.severity}")
        print()
        
        # 4. Toma decisão
        print("4️⃣  Tomando decisão...")
        decision = self.policy.make_decision(scoring_result)
        print(f"   ✅ Ação: {decision.action.value.upper()}")
        print(f"      Razão: {decision.reason}")
        print()
        
        # 5. Loga
        print("5️⃣  Logando evento...")
        self.logger.log_event(event, scoring_result, decision)
        print(f"   ✅ Evento logado")
        print()
        
        return {
            'scan': scan_result,
            'event': event.to_dict(),
            'scoring': scoring_result.to_dict(),
            'decision': decision.to_dict(),
        }
    
    async def test_recon_integration(self, target: str):
        """Testa integração com recon passivo"""
        print("=" * 80)
        print(f"🔍 PASSIVE RECON + UMBRA CORE: {target}")
        print("=" * 80)
        print()
        
        # 1. Roda recon
        print("1️⃣  Executando recon passivo...")
        recon_result = await passive_recon(
            target=target,
            include_subdomains=False,
            include_asn=True
        )
        
        print(f"   ✅ Recon completo")
        print()
        
        # 2. Converte para Event
        print("2️⃣  Convertendo para Event...")
        event = self.adapter.from_passive_recon(recon_result)
        print(f"   ✅ Event criado: {event.event_id}")
        print()
        
        # 3-5. Processa no Core (mesmo fluxo)
        scoring_result = self.engine.calculate_score(event)
        decision = self.policy.make_decision(scoring_result)
        self.logger.log_event(event, scoring_result, decision)
        
        print(f"3️⃣  Score: {scoring_result.final_score:.3f} | Severidade: {scoring_result.severity}")
        print(f"4️⃣  Decisão: {decision.action.value.upper()}")
        print(f"5️⃣  Evento logado")
        print()
        
        return {
            'recon': recon_result,
            'event': event.to_dict(),
            'scoring': scoring_result.to_dict(),
            'decision': decision.to_dict(),
        }


async def main():
    """Execução principal"""
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 18 + "TESTE DE INTEGRAÇÃO: SCANNERS + CORE" + " " * 24 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    integration = UmbraIntegration()
    
    # Teste 1: Port scan no localhost
    print("📋 TESTE 1: Port Scan Integration")
    result1 = await integration.test_port_scan_integration('127.0.0.1')
    
    print()
    input("Pressione ENTER para continuar...")
    print()
    
    # Teste 2: Recon passivo
    print("📋 TESTE 2: Passive Recon Integration")
    result2 = await integration.test_recon_integration('8.8.8.8')
    
    print()
    print("=" * 80)
    print("✅ INTEGRAÇÃO TESTADA COM SUCESSO!")
    print("=" * 80)
    print()
    
    # Mostra estatísticas
    print("📊 Estatísticas:")
    print(f"   Engine: {integration.engine.get_stats()}")
    print(f"   Policy: {integration.policy.get_stats()}")
    print(f"   Logger: {integration.logger.get_stats()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Teste interrompido.")
    except Exception as e:
        print(f"\n❌ ERRO: {e}")
        import traceback
        traceback.print_exc()