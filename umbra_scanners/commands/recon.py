"""
Umbra Scanners - Comando: recon
Reconhecimento passivo (OSINT).
"""

import click
import asyncio
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from recon.passive_osint import passive_recon
from core.logger import setup_logger
from core.utils import generate_trace_id

console = Console()


@click.command(name='recon')
@click.argument('target')
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Salva resultado em arquivo JSON'
)
@click.option(
    '--no-subdomains',
    is_flag=True,
    help='Desabilita busca de subdomínios (mais rápido)'
)
@click.option(
    '--no-asn',
    is_flag=True,
    help='Desabilita lookup de ASN/Geolocation'
)
@click.option(
    '--timeout',
    type=int,
    default=10,
    help='Timeout em segundos (padrão: 10)'
)
@click.option(
    '--format',
    type=click.Choice(['json', 'table', 'both']),
    default='table',
    help='Formato de saída (padrão: table)'
)
@click.pass_context
def recon_cmd(ctx, target, output, no_subdomains, no_asn, timeout, format):
    """
    Realiza reconhecimento passivo (OSINT) de um alvo.
    
    TARGET pode ser um IP, domínio ou URL.
    
    Exemplos:
    
      umbra recon example.com
      
      umbra recon 8.8.8.8 --no-subdomains
      
      umbra recon example.com -o results.json --format json
    """
    
    # Configura logger
    log_level = ctx.obj.get('log_level', 'INFO')
    logger = setup_logger(name='umbra.recon', level=log_level)
    
    # Gera trace_id
    trace_id = generate_trace_id()
    
    # Mostra banner
    if not ctx.obj.get('quiet'):
        console.print()
        console.print(Panel.fit(
            f"🔍 [bold cyan]Umbra Recon[/bold cyan] - Passive OSINT\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Trace ID: [dim]{trace_id}[/dim]",
            border_style="cyan"
        ))
        console.print()
    
    # Executa passive recon
    try:
        with console.status("[bold cyan]Coletando informações...", spinner="dots"):
            result = asyncio.run(
                passive_recon(
                    target=target,
                    trace_id=trace_id,
                    include_subdomains=not no_subdomains,
                    include_asn=not no_asn,
                    timeout=timeout
                )
            )
        
        # Verifica se teve erro
        if 'error' in result:
            console.print(f"[red]❌ Erro:[/red] {result['error']}")
            raise click.Abort()
        
        # Exibe resultado
        if format in ['table', 'both']:
            display_recon_table(result)
        
        if format in ['json', 'both']:
            console.print()
            console.print("[cyan]JSON Output:[/cyan]")
            console.print_json(data=result)
        
        # Salva em arquivo se solicitado
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            
            console.print()
            console.print(f"[green]✓[/green] Resultado salvo em: {output_path}")
        
        # Resumo final
        if not ctx.obj.get('quiet'):
            console.print()
            console.print(
                f"[green]✓[/green] Scan completo em "
                f"[cyan]{result['meta']['scan_time_s']}s[/cyan] | "
                f"Score: [yellow]{result.get('score_total', 0)}[/yellow]"
            )
            console.print()
    
    except Exception as e:
        logger.error('recon_failed', error=str(e), exc_info=True)
        console.print(f"\n[red]❌ Erro durante scan:[/red] {e}")
        raise click.Abort()


def display_recon_table(result: dict):
    """Exibe resultado em formato de tabela bonita."""
    
    results = result.get('results', {})
    
    # ============================================
    # Tabela: Informações Gerais
    # ============================================
    
    general_table = Table(
        title="📋 Informações Gerais",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    general_table.add_column("Campo", style="cyan")
    general_table.add_column("Valor", style="white")
    
    general_table.add_row("Target", result.get('target', 'N/A'))
    general_table.add_row("Tipo", result.get('target_type', 'N/A'))
    general_table.add_row("Timestamp", result.get('timestamp', 'N/A'))
    general_table.add_row("Score", str(result.get('score_total', 0)))
    
    if 'resolved_ip' in results:
        general_table.add_row("IP Resolvido", results['resolved_ip'] or 'N/A')
    
    console.print(general_table)
    console.print()
    
    # ============================================
    # Tabela: Whois
    # ============================================
    
    whois_data = results.get('whois')
    if whois_data:
        whois_table = Table(
            title="🔖 Whois Information",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow"
        )
        whois_table.add_column("Campo", style="yellow")
        whois_table.add_column("Valor", style="white")
        
        whois_table.add_row("Registrar", whois_data.get('registrar', 'N/A'))
        whois_table.add_row("Org", whois_data.get('org', 'N/A'))
        whois_table.add_row("País", whois_data.get('country', 'N/A'))
        whois_table.add_row("Criação", str(whois_data.get('creation_date', 'N/A'))[:10])
        whois_table.add_row("Expiração", str(whois_data.get('expiration_date', 'N/A'))[:10])
        
        name_servers = whois_data.get('name_servers', [])
        if name_servers:
            whois_table.add_row(
                "Name Servers",
                '\n'.join(name_servers[:3]) if isinstance(name_servers, list) else str(name_servers)
            )
        
        console.print(whois_table)
        console.print()
    
    # ============================================
    # Tabela: DNS Records
    # ============================================
    
    dns_data = results.get('dns', {})
    if dns_data:
        dns_table = Table(
            title="🌐 DNS Records",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green"
        )
        dns_table.add_column("Tipo", style="green")
        dns_table.add_column("Registros", style="white")
        
        for record_type, records in dns_data.items():
            if records:
                dns_table.add_row(
                    record_type,
                    '\n'.join(records[:5]) if len(records) > 5 else '\n'.join(records)
                )
        
        if dns_table.row_count > 0:
            console.print(dns_table)
            console.print()
    
    # ============================================
    # Tabela: Subdomínios
    # ============================================
    
    subdomains = results.get('subdomains', [])
    if subdomains:
        sub_table = Table(
            title=f"🔗 Subdomínios Encontrados ({len(subdomains)})",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        sub_table.add_column("Subdomínio", style="magenta")
        
        for subdomain in subdomains[:20]:  # Limita a 20
            sub_table.add_row(subdomain)
        
        if len(subdomains) > 20:
            sub_table.add_row(f"[dim]... e mais {len(subdomains) - 20} subdomínios[/dim]")
        
        console.print(sub_table)
        console.print()
    
    # ============================================
    # Tabela: ASN / Geolocation
    # ============================================
    
    asn_data = results.get('asn')
    if asn_data:
        asn_table = Table(
            title="🌍 ASN & Geolocation",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold blue"
        )
        asn_table.add_column("Campo", style="blue")
        asn_table.add_column("Valor", style="white")
        
        asn_table.add_row("IP", asn_data.get('ip', 'N/A'))
        asn_table.add_row("Hostname", asn_data.get('hostname', 'N/A') or 'N/A')
        asn_table.add_row("Organização", asn_data.get('org', 'N/A'))
        asn_table.add_row("País", asn_data.get('country', 'N/A'))
        asn_table.add_row("Cidade", asn_data.get('city', 'N/A') or 'N/A')
        asn_table.add_row("Coordenadas", asn_data.get('loc', 'N/A') or 'N/A')
        asn_table.add_row("Timezone", asn_data.get('timezone', 'N/A') or 'N/A')
        
        console.print(asn_table)
        console.print()
    
    # ============================================
    # Tabela: Reverse DNS
    # ============================================
    
    rdns = results.get('reverse_dns')
    if rdns:
        console.print(f"[bold cyan]🔄 Reverse DNS:[/bold cyan] {rdns}")
        console.print()