"""
log_formatter.py
----------------
Utilitário para formatar logs de forma visual e intuitiva.

Modos de visualização:
- "pretty" (padrão): Formato visual com quadros e seções detalhadas
- "compact": Formato compacto de 1 linha por evento (grep-friendly)

Para mudar o modo, defina a variável de ambiente:
  export LOG_VIEW_MODE=compact  # ou pretty

Características:
- Trace IDs para correlação de eventos
- IDs derivados para CEKs (nunca expõe a chave real)
- Truncamento consistente de valores hexadecimais
- Numeração linear contínua
- Campos fixos por bloco (ordem padronizada)
- Redução de exposição de segredos
"""
import uuid
import hashlib
import os

# Modo de visualização: "compact" ou "pretty"
LOG_VIEW_MODE = os.getenv("LOG_VIEW_MODE", "pretty").lower()

def truncate_hex(value: str, prefix_len: int = 6, suffix_len: int = 6) -> str:
    """
    Trunca valores hexadecimais de forma consistente.
    
    Args:
        value: Valor hexadecimal
        prefix_len: Comprimento do prefixo
        suffix_len: Comprimento do sufixo
    
    Returns:
        Valor truncado no formato: AB12CD...EF3456
    """
    if not value:
        return ""
    value = value.upper()
    if len(value) <= prefix_len + suffix_len:
        return value
    return f"{value[:prefix_len]}...{value[-suffix_len:]}"

def derive_cek_id(cek_bytes: bytes) -> str:
    """
    Deriva um ID seguro da CEK sem expor o valor real.
    
    Args:
        cek_bytes: Bytes da CEK
    
    Returns:
        ID hexadecimal truncado (6 caracteres)
    """
    cek_hash = hashlib.sha256(cek_bytes).hexdigest()
    return truncate_hex(cek_hash, 6, 0)

def derive_msg_id(content: str) -> str:
    """
    Deriva um ID da mensagem a partir do conteúdo.
    
    Args:
        content: Conteúdo da mensagem
    
    Returns:
        ID hexadecimal truncado
    """
    msg_hash = hashlib.sha256(content.encode()).hexdigest()
    return truncate_hex(msg_hash, 6, 6)

def new_trace_id() -> str:
    """
    Gera um novo trace_id para correlacionar eventos.
    
    Returns:
        UUID formatado como string (primeiros 8 caracteres)
    """
    return str(uuid.uuid4())[:8]

def format_box(title: str, content: list, width: int = 70, char: str = "=") -> str:
    """
    Cria um quadro formatado com título e conteúdo.
    
    Args:
        title: Título do quadro
        content: Lista de linhas de conteúdo
        width: Largura do quadro
        char: Caractere usado para as bordas
    
    Returns:
        String formatada com o quadro
    """
    lines = []
    lines.append(char * width)
    lines.append(f"  {title}")
    lines.append(char * width)
    for line in content:
        lines.append(f"  {line}")
    lines.append(char * width)
    return "\n".join(lines)


def format_section(title: str, items: dict, width: int = 70, trace_id: str = None) -> str:
    """
    Cria uma seção formatada com título e itens chave-valor.
    
    Args:
        title: Título da seção
        items: Dicionário de itens (chave: valor) - valores serão truncados
        width: Largura da seção
        trace_id: ID de rastreamento (opcional)
    
    Returns:
        String formatada
    """
    if LOG_VIEW_MODE == "compact":
        # Modo compacto: 1 linha
        trace_str = f" [#t={trace_id}]" if trace_id else ""
        items_str = " | ".join([f"{k}={truncate_hex(str(v)) if isinstance(v, str) and len(str(v)) > 12 else v}" for k, v in items.items() if v])
        return f"[{title}]{trace_str} | {items_str}"
    
    # Modo pretty: formato completo
    lines = []
    lines.append(f"\n{'─' * width}")
    lines.append(f"  📋 {title}")
    if trace_id:
        lines.append(f"  🔍 Trace ID: {trace_id}")
    lines.append(f"{'─' * width}")
    # Ordem fixa para campos comuns
    order = ["Grupo", "Remetente", "Destinatário", "Total de membros", "Msg ID", "CEK ID", "CEK gerada"]
    for key in order:
        if key in items and items[key]:
            value = items[key]
            # Trunca valores hexadecimais
            if isinstance(value, str) and len(value) > 20 and all(c in '0123456789ABCDEFabcdef' for c in value.replace('...', '')):
                value = truncate_hex(value)
            lines.append(f"  • {key}: {value}")
    # Campos adicionais
    for key, value in items.items():
        if key not in order and value:
            if isinstance(value, str) and len(value) > 20 and all(c in '0123456789ABCDEFabcdef' for c in value.replace('...', '')):
                value = truncate_hex(value)
            lines.append(f"  • {key}: {value}")
    lines.append(f"{'─' * width}\n")
    return "\n".join(lines)


def format_flow(actor: str, action: str, target: str, details: dict = None, width: int = 70, trace_id: str = None) -> str:
    """
    Formata um fluxo de ação (quem faz o quê para quem).
    
    Args:
        actor: Quem executa a ação
        action: Ação executada
        target: Destinatário da ação
        details: Detalhes adicionais (opcional)
        width: Largura do formato
        trace_id: ID de rastreamento (opcional)
    
    Returns:
        String formatada
    """
    if LOG_VIEW_MODE == "compact":
        # Modo compacto: 1 linha
        trace_str = f" [#t={trace_id}]" if trace_id else ""
        details_str = " | ".join([f"{k}={v}" for k, v in (details or {}).items() if v])
        if details_str:
            return f"[{action}] {actor} → {target}{trace_str} | {details_str}"
        return f"[{action}] {actor} → {target}{trace_str}"
    
    # Modo pretty: formato completo
    lines = []
    lines.append(f"\n{'═' * width}")
    lines.append(f"  👤 {actor}  →  {action}  →  👥 {target}")
    if trace_id:
        lines.append(f"  🔍 Trace ID: {trace_id}")
    lines.append(f"{'═' * width}")
    if details:
        # Ordem fixa: Tipo, Grupo, Msg ID, CEK ID, Algoritmo/IV
        order = ["Tipo", "Grupo", "Msg ID", "CEK ID", "Algoritmo", "IV"]
        for key in order:
            if key in details and details[key]:
                lines.append(f"  │ {key}: {details[key]}")
        # Campos adicionais
        for key, value in details.items():
            if key not in order and value:
                lines.append(f"  │ {key}: {value}")
    lines.append(f"{'═' * width}\n")
    return "\n".join(lines)


def format_step(step_num: int, description: str, data: dict = None, width: int = 70, trace_id: str = None) -> str:
    """
    Formata um passo do processo.
    
    Args:
        step_num: Número do passo
        description: Descrição do passo
        data: Dados adicionais (opcional) - valores serão truncados automaticamente
        width: Largura do formato
        trace_id: ID de rastreamento (opcional)
    
    Returns:
        String formatada
    """
    if LOG_VIEW_MODE == "compact":
        # Modo compacto: 1 linha
        trace_str = f" [#t={trace_id}]" if trace_id else ""
        data_str = " | ".join([f"{k}={truncate_hex(str(v)) if isinstance(v, str) and len(str(v)) > 12 else v}" for k, v in (data or {}).items() if v])
        if data_str:
            return f"[{step_num}] {description}{trace_str} | {data_str}"
        return f"[{step_num}] {description}{trace_str}"
    
    # Modo pretty: formato completo
    lines = []
    lines.append(f"{'─' * width}")
    trace_str = f" [#t={trace_id}]" if trace_id else ""
    lines.append(f"  [{step_num}] {description}{trace_str}")
    if data:
        # Trunca valores sensíveis automaticamente
        for key, value in data.items():
            if value:
                # Trunca valores hexadecimais longos
                if isinstance(value, str):
                    if len(value) > 20 and all(c in '0123456789ABCDEFabcdef' for c in value.replace('...', '')):
                        value = truncate_hex(value)
                    elif len(value) > 60:
                        value = value[:30] + "..." + value[-30:]
                lines.append(f"     └─ {key}: {value}")
    lines.append(f"{'─' * width}")
    return "\n".join(lines)


def format_group_distribution(sender: str, group_name: str, members: list, width: int = 70, trace_id: str = None) -> str:
    """
    Formata a distribuição de mensagens/chaves para um grupo (resumo final).
    
    Args:
        sender: Remetente
        group_name: Nome do grupo
        members: Lista de membros que receberam
        width: Largura do formato
        trace_id: ID de rastreamento (opcional)
    
    Returns:
        String formatada
    """
    if LOG_VIEW_MODE == "compact":
        trace_str = f" [#t={trace_id}]" if trace_id else ""
        members_str = ", ".join(members)
        return f"[DISTRIBUIÇÃO CONCLUÍDA]{trace_str} | {sender} → Grupo '{group_name}' | Membros: {members_str}"
    
    lines = []
    lines.append(f"\n{'═' * width}")
    lines.append(f"  📤 DISTRIBUIÇÃO CONCLUÍDA: {sender} → Grupo '{group_name}'")
    if trace_id:
        lines.append(f"  🔍 Trace ID: {trace_id}")
    lines.append(f"  👥 Membros que receberam: {len(members)}")
    lines.append(f"{'═' * width}")
    for i, member in enumerate(members, 1):
        lines.append(f"  [{i}] {member}")
    lines.append(f"{'═' * width}\n")
    return "\n".join(lines)


def format_key_info(label: str, value: str, use_id: bool = True, width: int = 70) -> str:
    """
    Formata informações de chave (sempre truncado ou ID derivado).
    
    Args:
        label: Rótulo da chave
        value: Valor da chave (hexadecimal)
        use_id: Se True, deriva um ID; se False, apenas trunca
        width: Largura do formato (não usado, mantido para compatibilidade)
    
    Returns:
        String formatada
    """
    if use_id and isinstance(value, str) and len(value) > 16:
        # Para CEKs, usa ID derivado
        try:
            cek_bytes = bytes.fromhex(value)
            display_value = derive_cek_id(cek_bytes)
        except:
            display_value = truncate_hex(value)
    else:
        display_value = truncate_hex(value) if len(value) > 12 else value
    
    return f"  🔑 {label}: {display_value}"


def format_success(message: str, width: int = 70) -> str:
    """
    Formata uma mensagem de sucesso.
    
    Args:
        message: Mensagem de sucesso
        width: Largura do formato
    
    Returns:
        String formatada
    """
    lines = []
    lines.append(f"\n{'═' * width}")
    lines.append(f"  ✅ {message}")
    lines.append(f"{'═' * width}\n")
    return "\n".join(lines)

