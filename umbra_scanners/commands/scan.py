"""
Umbra Scanners - Comando: scan
Port scanning (TCP Connect).
"""

import click
import asyncio
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from recon.active_scan import active_scan
from core.logger import setup_logger
from core.utils import generate_trace_id, parse_port_range

console = Console()


@click.command(name='scan')
@click.argument('target')
@click.option(
    '--ports', '-p',
    default='1-1000',
    help='Portas ou range (ex: 80,443 ou 1-1000). Padrão: top 1000'
)
@click.option(
    '--timeout', '-t',
    type=int,
    default=3,
    help='Timeout por porta em segundos (padrão: 3)'
)
@click.option(
    '--fast',
    is_flag=True,
    help='Scan rápido (apenas top 100 portas)'
)
@click.option(
    '--no-banner',
    is_flag=True,
    help='Não captura banners (mais rápido)'
)
@click.option(
    '--max-concurrent',
    type=int,
    default=100,
    help='Máximo de scans simultâneos (padrão: 100)'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Salva resultado em arquivo JSON'
)
@click.option(
    '--format',
    type=click.Choice(['json', 'table', 'both']),
    default='table',
    help='Formato de saída (padrão: table)'
)
@click.pass_context
def scan_cmd(ctx, target, ports, timeout, fast, no_banner, max_concurrent, output, format):
    """
    Realiza port scan TCP em um alvo.
    
    TARGET pode ser um IP ou domínio.
    
    Exemplos:
    
      umbra scan 127.0.0.1
      
      umbra scan 192.168.1.1 --ports 80,443,22
      
      umbra scan example.com --fast
      
      umbra scan 10.0.0.1 --ports 1-100 --timeout 1
    """
    
    # Configura logger
    log_level = ctx.obj.get('log_level', 'INFO')
    logger = setup_logger(name='umbra.scan', level=log_level)
    
    # Gera trace_id
    trace_id = generate_trace_id()
    
    # Valida portas
    if not fast:
        try:
            port_list = parse_port_range(ports)
            if not port_list:
                console.print("[red]❌ Erro:[/red] Range de portas inválido")
                raise click.Abort()
        except Exception as e:
            console.print(f"[red]❌ Erro ao parsear portas:[/red] {e}")
            raise click.Abort()
    else:
        port_list = None  # fast_mode usa lista interna
    
    # Mostra banner
    if not ctx.obj.get('quiet'):
        console.print()
        
        scan_info = f"Target: [yellow]{target}[/yellow]\n"
        
        if fast:
            scan_info += "Mode: [cyan]Fast (top 100 portas)[/cyan]\n"
        else:
            scan_info += f"Portas: [cyan]{ports}[/cyan] ({len(port_list) if port_list else '?'} portas)\n"
        
        scan_info += f"Timeout: [cyan]{timeout}s[/cyan]\n"
        scan_info += f"Banner Grab: [cyan]{'Não' if no_banner else 'Sim'}[/cyan]\n"
        scan_info += f"Trace ID: [dim]{trace_id}[/dim]"
        
        console.print(Panel.fit(
            f"🔍 [bold cyan]Umbra Port Scanner[/bold cyan]\n{scan_info}",
            border_style="cyan"
        ))
        console.print()
    
    # Executa scan com progress bar
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Escaneando portas...", total=None)
            
            result = asyncio.run(
                active_scan(
                    target=target,
                    ports=port_list,
                    fast_mode=fast,
                    timeout=timeout,
                    max_concurrent=max_concurrent,
                    grab_banner=not no_banner,
                    trace_id=trace_id
                )
            )
            
            progress.update(task, completed=True)
        
        # Verifica se teve erro
        if 'error' in result:
            console.print(f"[red]❌ Erro:[/red] {result['error']}")
            raise click.Abort()
        
        # Exibe resultado
        if format in ['table', 'both']:
            display_scan_table(result)
        
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
            meta = result['meta']
            console.print()
            console.print(
                f"[green]✓[/green] Scan completo em [cyan]{meta['scan_time_s']}s[/cyan] | "
                f"Portas abertas: [yellow]{meta['ports_open']}/{meta['ports_scanned']}[/yellow] | "
                f"Score: [{'red' if result.get('score_total', 0) > 1.0 else 'yellow'}]{result.get('score_total', 0)}[/]"
            )
            console.print()
    
    except Exception as e:
        logger.error('scan_failed', error=str(e), exc_info=True)
        console.print(f"\n[red]❌ Erro durante scan:[/red] {e}")
        raise click.Abort()


def display_scan_table(result: dict):
    """Exibe resultado em formato de tabela bonita."""
    
    meta = result.get('meta', {})
    results = result.get('results', [])
    
    # ============================================
    # Tabela: Resumo do Scan
    # ============================================
    
    summary_table = Table(
        title="📊 Resumo do Scan",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    summary_table.add_column("Métrica", style="cyan")
    summary_table.add_column("Valor", style="white")
    
    summary_table.add_row("Target", result.get('target', 'N/A'))
    summary_table.add_row("IP", result.get('target_ip', 'N/A'))
    summary_table.add_row("Portas Escaneadas", str(meta.get('ports_scanned', 0)))
    summary_table.add_row("Portas Abertas", f"[green]{meta.get('ports_open', 0)}[/green]")
    summary_table.add_row("Portas Fechadas", f"[dim]{meta.get('ports_closed', 0)}[/dim]")
    summary_table.add_row("Portas Filtradas", f"[yellow]{meta.get('ports_filtered', 0)}[/yellow]")
    summary_table.add_row("Tempo de Scan", f"{meta.get('scan_time_s', 0)}s")
    summary_table.add_row("Score Total", str(result.get('score_total', 0)))
    
    console.print(summary_table)
    console.print()
    
    # ============================================
    # Tabela: Portas Abertas
    # ============================================
    
    if results:
        ports_table = Table(
            title=f"🔓 Portas Abertas ({len(results)})",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green"
        )
        ports_table.add_column("Porta", style="green", justify="right")
        ports_table.add_column("Serviço", style="cyan")
        ports_table.add_column("Banner", style="white")
        ports_table.add_column("Resp. (ms)", style="yellow", justify="right")
        ports_table.add_column("Score", style="red", justify="right")
        
        for port_result in results:
            # Trunca banner se muito longo
            banner = port_result.get('banner', '')
            if banner:
                banner = banner.replace('\n', ' ').replace('\r', ' ')
                if len(banner) > 50:
                    banner = banner[:47] + '...'
            else:
                banner = '[dim]N/A[/dim]'
            
            # Estiliza score
            score = port_result.get('score', 0)
            if score >= 0.8:
                score_str = f"[red bold]{score}[/red bold]"
            elif score >= 0.5:
                score_str = f"[yellow]{score}[/yellow]"
            else:
                score_str = f"[green]{score}[/green]"
            
            ports_table.add_row(
                str(port_result['port']),
                port_result.get('service') or '[dim]unknown[/dim]',
                banner,
                str(round(port_result.get('response_time_ms', 0), 1)),
                score_str
            )
        
        console.print(ports_table)
        console.print()
    
    else:
        console.print("[yellow]ℹ️  Nenhuma porta aberta encontrada.[/yellow]")
        console.print()