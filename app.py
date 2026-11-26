import os
import sys
import re
import time
import sqlite3
import threading
import webbrowser
import urllib.request
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import webview
    TEM_WEBVIEW = True
except ImportError:
    TEM_WEBVIEW = False

# --- CONFIGURAÇÃO DE CAMINHOS (MODO DESENVOLVIMENTO E MODO .EXE) ---
if getattr(sys, 'frozen', False):
    PASTA_RECURSOS = sys._MEIPASS
    PASTA_EXECUTAVEL = os.path.dirname(sys.executable)
else:
    PASTA_RECURSOS = os.path.dirname(os.path.abspath(__file__))
    PASTA_EXECUTAVEL = PASTA_RECURSOS

PASTA_TEMPLATES = os.path.join(PASTA_RECURSOS, 'templates')
PASTA_STATIC = os.path.join(PASTA_RECURSOS, 'static')
DB_PATH = os.path.join(PASTA_EXECUTAVEL, 'pdv.db')
ICON_PATH = os.path.join(PASTA_RECURSOS, 'icone_novo.ico')

if os.path.isdir(PASTA_STATIC):
    app = Flask(__name__, template_folder=PASTA_TEMPLATES, static_folder=PASTA_STATIC)
else:
    app = Flask(__name__, template_folder=PASTA_TEMPLATES)

app.secret_key = 'gr_pdv_#2026_chave_ultra_segura_v2'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

TENTATIVAS_LOGIN = {}  # Controle contra força bruta: {ip: {'falhas': int, 'bloqueado_ate': float}}

# --- CONEXÃO E INICIALIZAÇÃO SEGURA DO BANCO ---

def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def formatar_brl(valor):
    return f"{float(valor or 0):,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

def registrar_auditoria(conn, acao, detalhes, usuario_nome=None):
    autor = usuario_nome or session.get('usuario_nome', 'Sistema')
    conn.execute(
        "INSERT INTO logs_auditoria (usuario_nome, acao, detalhes) VALUES (?, ?, ?)",
        (autor, acao, detalhes)
    )

def inicializar_banco():
    conn = db_connect()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            senha TEXT NOT NULL,
            cargo TEXT NOT NULL CHECK(cargo IN ('funcionario', 'fiscal', 'gerente'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT NOT NULL UNIQUE,
            descricao TEXT NOT NULL,
            categoria TEXT,
            estoque INTEGER NOT NULL DEFAULT 0 CHECK(estoque >= 0),
            preco_custo REAL NOT NULL DEFAULT 0 CHECK(preco_custo >= 0),
            preco_venda REAL NOT NULL CHECK(preco_venda > 0)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vendas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resumo_itens TEXT NOT NULL,
            valor_total REAL NOT NULL CHECK(valor_total > 0),
            forma_pagamento TEXT NOT NULL,
            usuario_id INTEGER,
            data_venda TEXT DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_nome TEXT NOT NULL,
            acao TEXT NOT NULL,
            detalhes TEXT,
            data_hora TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)

    # Cria usuários iniciais com senha criptografada (senha padrão: 1234)
    usuarios_iniciais = [
        ('João Operador', 'caixa', generate_password_hash('1234'), 'funcionario'),
        ('Carlos Fiscal', 'fiscal', generate_password_hash('1234'), 'fiscal'),
        ('Arthur Gerente', 'gerente', generate_password_hash('1234'), 'gerente')
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO usuarios (nome, usuario, senha, cargo) VALUES (?, ?, ?, ?)",
        usuarios_iniciais
    )

    # Migração automática caso existam senhas antigas sem hash no banco local
    rows_users = cursor.execute("SELECT id, senha FROM usuarios").fetchall()
    for u in rows_users:
        if not u['senha'].startswith(('pbkdf2:', 'scrypt:')):
            cursor.execute(
                "UPDATE usuarios SET senha = ? WHERE id = ?",
                (generate_password_hash(u['senha']), u['id'])
            )

    produtos_iniciais = [
        ('2105800005168', 'PRESUNTO DE PERU SADIA', 'Frios', 120, 10.50, 14.99),
        ('2006800001146', 'SABUGUEIRO', 'Chás', 45, 60.00, 95.00),
        ('2025400002452', 'SEMENTE DE JERIMUN', 'Sementes', 850, 20.00, 35.00),
        ('7891000100103', 'LEITE INTEGRAL NINHO 1L', 'Laticínios', 50, 4.20, 5.99),
        ('7894900011517', 'COCA-COLA 2L', 'Bebidas', 36, 6.50, 9.50),
        ('7891991010856', 'ARROZ TIPO 1 CAMIL 5KG', 'Mercearia', 8, 19.50, 26.90)
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO produtos (codigo, descricao, categoria, estoque, preco_custo, preco_venda) VALUES (?, ?, ?, ?, ?, ?)",
        produtos_iniciais
    )

    conn.commit()
    conn.close()

# --- DECORADORES DE SEGURANÇA (RBAC) ---

def exigir_login(api=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'usuario_id' not in session:
                if api:
                    return jsonify({'erro': 'Sessão expirada. Faça login novamente.'}), 401
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

def exigir_cargo(cargos_permitidos, api=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'usuario_id' not in session:
                if api:
                    return jsonify({'erro': 'Sessão expirada. Faça login novamente.'}), 401
                return redirect(url_for('login'))
            if session.get('cargo') not in cargos_permitidos:
                if api:
                    return jsonify({'erro': 'Acesso negado! Seu cargo não possui permissão para esta ação.'}), 403
                return redirect(url_for('tela_caixa'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- TRATAMENTO GLOBAL DE ERROS ---

@app.errorhandler(404)
def erro_404(e):
    if request.path.startswith('/api/'):
        return jsonify({'erro': 'Rota da API não encontrada.'}), 404
    return redirect(url_for('tela_caixa'))

@app.errorhandler(500)
def erro_500(e):
    if request.path.startswith('/api/'):
        return jsonify({'erro': 'Erro interno no servidor. Tente novamente.'}), 500
    return "Erro interno no servidor.", 500

# --- AUTENTICAÇÃO ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr or 'local'
        agora = time.time()
        registro_ip = TENTATIVAS_LOGIN.get(ip, {'falhas': 0, 'bloqueado_ate': 0})

        if agora < registro_ip['bloqueado_ate']:
            segundos = int(registro_ip['bloqueado_ate'] - agora)
            return render_template('login.html', erro=f'Muitas tentativas! Aguarde {segundos}s para tentar novamente.')

        usuario_digitado = request.form.get('usuario', '').strip().lower()
        senha_digitada = request.form.get('senha', '').strip()

        if not usuario_digitado or not senha_digitada:
            return render_template('login.html', erro='Preencha usuário e senha!')

        conn = db_connect()
        row = conn.execute(
            "SELECT * FROM usuarios WHERE LOWER(usuario) = ?",
            (usuario_digitado,)
        ).fetchone()

        if row and check_password_hash(row['senha'], senha_digitada):
            user = dict(row)
            TENTATIVAS_LOGIN.pop(ip, None)
            session.clear()
            session['usuario_id'] = user['id']
            session['usuario_nome'] = user['nome']
            session['cargo'] = user['cargo']
            registrar_auditoria(conn, 'LOGIN', f"Acesso ao sistema ({user['cargo'].upper()})", user['nome'])
            conn.commit()
            conn.close()
            return redirect(url_for('tela_caixa'))

        conn.close()
        registro_ip['falhas'] += 1
        if registro_ip['falhas'] >= 5:
            registro_ip['bloqueado_ate'] = agora + 30
            registro_ip['falhas'] = 0
        TENTATIVAS_LOGIN[ip] = registro_ip
        return render_template('login.html', erro='Usuário ou senha incorretos!')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'usuario_nome' in session:
        conn = db_connect()
        registrar_auditoria(conn, 'LOGOUT', 'Saída do sistema')
        conn.commit()
        conn.close()
    session.clear()
    return redirect(url_for('login'))

# --- TELAS ---

@app.route('/')
@exigir_login(api=False)
def tela_caixa():
    return render_template('caixa.html', usuario_nome=session['usuario_nome'], cargo=session['cargo'])

@app.route('/estoque')
@exigir_cargo(['fiscal', 'gerente'], api=False)
def tela_estoque():
    conn = db_connect()
    rows = conn.execute("SELECT * FROM produtos ORDER BY id DESC").fetchall()
    conn.close()

    produtos = [dict(r) for r in rows]
    total_produtos = len(produtos)
    estoque_baixo = sum(1 for p in produtos if p['estoque'] < 10)
    valor_total_compra = sum((float(p['preco_custo'] or 0) * p['estoque']) for p in produtos)

    return render_template(
        'estoque.html',
        produtos=produtos,
        total_produtos=total_produtos,
        estoque_baixo=estoque_baixo,
        valor_total_compra=formatar_brl(valor_total_compra),
        usuario_nome=session['usuario_nome'],
        cargo=session['cargo']
    )

@app.route('/gerencia')
@exigir_cargo(['gerente'], api=False)
def tela_gerencia():
    conn = db_connect()
    vendas_rows = conn.execute("""
        SELECT v.*, COALESCE(u.nome, 'Operador Removido') AS operador_nome
        FROM vendas v
        LEFT JOIN usuarios u ON v.usuario_id = u.id
        ORDER BY v.id DESC
    """).fetchall()
    usuarios_rows = conn.execute("SELECT id, nome, usuario, cargo FROM usuarios ORDER BY id ASC").fetchall()
    logs_rows = conn.execute("SELECT * FROM logs_auditoria ORDER BY id DESC LIMIT 30").fetchall()
    conn.close()

    vendas = []
    for r in vendas_rows:
        v = dict(r)
        if isinstance(v.get('data_venda'), str):
            try:
                v['data_venda'] = datetime.strptime(v['data_venda'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                v['data_venda'] = None
        vendas.append(v)

    usuarios = [dict(u) for u in usuarios_rows]
    logs = [dict(l) for l in logs_rows]

    faturamento_total = sum(float(v['valor_total'] or 0) for v in vendas)
    total_pix = sum(float(v['valor_total'] or 0) for v in vendas if v['forma_pagamento'] == 'Pix')
    total_credito = sum(float(v['valor_total'] or 0) for v in vendas if v['forma_pagamento'] == 'Cartão de Crédito')
    total_debito = sum(float(v['valor_total'] or 0) for v in vendas if v['forma_pagamento'] == 'Cartão de Débito')
    total_dinheiro = sum(float(v['valor_total'] or 0) for v in vendas if v['forma_pagamento'] == 'Dinheiro')

    return render_template(
        'gerencia.html',
        vendas=vendas,
        usuarios=usuarios,
        logs=logs,
        qtd_vendas=len(vendas),
        faturamento_total=formatar_brl(faturamento_total),
        total_pix=formatar_brl(total_pix),
        total_credito=formatar_brl(total_credito),
        total_debito=formatar_brl(total_debito),
        total_dinheiro=formatar_brl(total_dinheiro),
        usuario_id_atual=session['usuario_id'],
        usuario_nome=session['usuario_nome'],
        cargo=session['cargo']
    )

# --- APIS DO CAIXA E SUPERVISÃO ---

@app.route('/api/buscar_produto', methods=['POST'])
@exigir_login(api=True)
def buscar_produto():
    dados = request.get_json(silent=True) or {}
    codigo = str(dados.get('codigo', '')).strip()

    if not re.fullmatch(r'\d{1,20}', codigo):
        return jsonify({'erro': 'Código de barras inválido! Digite apenas números.'}), 400

    conn = db_connect()
    row = conn.execute("SELECT * FROM produtos WHERE codigo = ?", (codigo,)).fetchone()
    conn.close()

    if row:
        produto = dict(row)
        produto['preco_venda'] = float(produto['preco_venda'])
        produto['preco_custo'] = float(produto['preco_custo'] or 0)
        return jsonify(produto)
    return jsonify({'erro': 'Produto não encontrado no estoque.'}), 404

@app.route('/api/pesquisar_produtos', methods=['POST'])
@exigir_login(api=True)
def pesquisar_produtos():
    dados = request.get_json(silent=True) or {}
    termo = str(dados.get('termo', '')).strip()[:50]

    conn = db_connect()
    rows = conn.execute(
        """SELECT codigo, descricao, categoria, estoque, preco_venda 
           FROM produtos 
           WHERE descricao LIKE ? OR codigo LIKE ? 
           ORDER BY descricao ASC LIMIT 25""",
        (f"%{termo}%", f"%{termo}%")
    ).fetchall()
    conn.close()

    resultado = []
    for r in rows:
        item = dict(r)
        item['preco_venda'] = float(item['preco_venda'])
        resultado.append(item)
    return jsonify(resultado)

@app.route('/api/autorizar_supervisor', methods=['POST'])
@exigir_login(api=True)
def autorizar_supervisor():
    dados = request.get_json(silent=True) or {}
    usuario = str(dados.get('usuario', '')).strip().lower()
    senha = str(dados.get('senha', '')).strip()
    motivo = str(dados.get('motivo', 'Cancelamento no caixa')).strip()[:100]

    if not usuario or not senha:
        return jsonify({'erro': 'Informe usuário e senha do supervisor.'}), 400

    conn = db_connect()
    row = conn.execute(
        "SELECT nome, senha, cargo FROM usuarios WHERE LOWER(usuario) = ? AND cargo IN ('fiscal', 'gerente')",
        (usuario,)
    ).fetchone()

    if row and check_password_hash(row['senha'], senha):
        registrar_auditoria(
            conn,
            'AUTORIZACAO_SUPERVISOR',
            f"Supervisor {row['nome']} ({row['cargo']}) autorizou: {motivo}"
        )
        conn.commit()
        conn.close()
        return jsonify({'autorizado': True, 'supervisor': row['nome']})

    conn.close()
    return jsonify({'erro': 'Credenciais inválidas ou usuário sem permissão de Fiscal/Gerente!'}), 403

@app.route('/api/finalizar_venda', methods=['POST'])
@exigir_login(api=True)
def finalizar_venda():
    dados = request.get_json(silent=True) or {}
    forma_pagamento = str(dados.get('forma_pagamento', '')).strip()
    itens = dados.get('itens_lista', [])

    formas_validas = {'Pix', 'Cartão de Crédito', 'Cartão de Débito', 'Dinheiro'}
    if forma_pagamento not in formas_validas:
        return jsonify({'erro': 'Forma de pagamento inválida!'}), 400

    if not isinstance(itens, list) or len(itens) == 0:
        return jsonify({'erro': 'O carrinho está vazio!'}), 400

    quantidades_por_codigo = {}
    for item in itens:
        codigo = str(item.get('codigo', '')).strip()
        try:
            quant = int(item.get('quant', 0))
        except (ValueError, TypeError):
            return jsonify({'erro': 'Quantidade inválida no carrinho.'}), 400

        if not re.fullmatch(r'\d{1,20}', codigo) or quant <= 0:
            return jsonify({'erro': 'Item ou quantidade inválida na venda.'}), 400

        quantidades_por_codigo[codigo] = quantidades_por_codigo.get(codigo, 0) + quant

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        total_calculado_servidor = 0.0
        partes_resumo = []

        for codigo, quant_total in quantidades_por_codigo.items():
            prod = conn.execute(
                "SELECT descricao, estoque, preco_venda FROM produtos WHERE codigo = ?",
                (codigo,)
            ).fetchone()

            if not prod:
                conn.rollback()
                return jsonify({'erro': f'Produto código {codigo} não existe mais no cadastro!'}), 400

            if prod['estoque'] < quant_total:
                conn.rollback()
                return jsonify({
                    'erro': f"Estoque insuficiente para '{prod['descricao']}'. Disponível: {prod['estoque']} un."
                }), 400

            subtotal = round(float(prod['preco_venda']) * quant_total, 2)
            total_calculado_servidor = round(total_calculado_servidor + subtotal, 2)
            partes_resumo.append(f"{quant_total}x {prod['descricao']}")

            conn.execute(
                "UPDATE produtos SET estoque = estoque - ? WHERE codigo = ?",
                (quant_total, codigo)
            )

        resumo_seguro = ", ".join(partes_resumo)
        conn.execute(
            "INSERT INTO vendas (resumo_itens, valor_total, forma_pagamento, usuario_id) VALUES (?, ?, ?, ?)",
            (resumo_seguro, total_calculado_servidor, forma_pagamento, session['usuario_id'])
        )
        registrar_auditoria(
            conn,
            'VENDA_FINALIZADA',
            f"Total: R$ {formatar_brl(total_calculado_servidor)} ({forma_pagamento})"
        )
        conn.commit()
        return jsonify({
            'mensagem': 'Venda finalizada com sucesso!',
            'total_confirmado': total_calculado_servidor
        })
    except Exception:
        conn.rollback()
        return jsonify({'erro': 'Falha ao processar a venda. Nenhuma alteração foi salva.'}), 500
    finally:
        conn.close()

# --- APIS DO ESTOQUE ---

@app.route('/api/cadastrar_produto', methods=['POST'])
@exigir_cargo(['fiscal', 'gerente'], api=True)
def cadastrar_produto():
    dados = request.get_json(silent=True) or {}
    codigo = str(dados.get('codigo', '')).strip()
    descricao = re.sub(r'\s+', ' ', str(dados.get('descricao', '')).strip().upper())
    categoria = re.sub(r'\s+', ' ', str(dados.get('categoria', '')).strip())

    if not re.fullmatch(r'\d{4,20}', codigo):
        return jsonify({'erro': 'Código inválido! Use apenas números (4 a 20 dígitos).'}), 400

    if len(descricao) < 3 or len(descricao) > 100 or not re.search(r'[A-ZÀ-Ÿ]', descricao):
        return jsonify({'erro': 'Descrição inválida! Informe um nome real entre 3 e 100 caracteres.'}), 400

    if categoria and not re.fullmatch(r'[A-Za-zÀ-ÿ\s]{3,40}', categoria):
        return jsonify({'erro': 'Categoria inválida! Use apenas letras (3 a 40 caracteres).'}), 400

    try:
        estoque = int(dados.get('estoque', -1))
        custo = round(float(dados.get('custo', 0)), 2)
        venda = round(float(dados.get('venda', 0)), 2)
    except (ValueError, TypeError):
        return jsonify({'erro': 'Valores numéricos inválidos!'}), 400

    if estoque < 0 or estoque > 999999:
        return jsonify({'erro': 'Estoque inicial inválido! Informe entre 0 e 999.999 unidades.'}), 400
    if custo < 0 or custo > 999999:
        return jsonify({'erro': 'Preço de custo inválido! Não são permitidos valores negativos.'}), 400
    if venda <= 0 or venda > 999999:
        return jsonify({'erro': 'Preço de venda inválido! Deve ser maior que R$ 0,00.'}), 400

    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO produtos (codigo, descricao, categoria, estoque, preco_custo, preco_venda) VALUES (?, ?, ?, ?, ?, ?)",
            (codigo, descricao, categoria, estoque, custo, venda)
        )
        registrar_auditoria(conn, 'PRODUTO_CADASTRADO', f"{codigo} - {descricao} ({estoque} un.)")
        conn.commit()
        return jsonify({'mensagem': 'Produto cadastrado com sucesso!'})
    except sqlite3.IntegrityError:
        return jsonify({'erro': 'Já existe um produto cadastrado com esse código de barras!'}), 400
    finally:
        conn.close()

@app.route('/api/repor_estoque', methods=['POST'])
@exigir_cargo(['fiscal', 'gerente'], api=True)
def repor_estoque():
    dados = request.get_json(silent=True) or {}
    codigo = str(dados.get('codigo', '')).strip()

    try:
        quantidade = int(dados.get('quantidade', 0))
    except (ValueError, TypeError):
        return jsonify({'erro': 'Quantidade inválida!'}), 400

    if quantidade <= 0 or quantidade > 100000:
        return jsonify({'erro': 'Informe uma quantidade inteira entre 1 e 100.000.'}), 400

    conn = db_connect()
    prod = conn.execute("SELECT descricao FROM produtos WHERE codigo = ?", (codigo,)).fetchone()
    if not prod:
        conn.close()
        return jsonify({'erro': 'Produto não encontrado!'}), 404

    conn.execute("UPDATE produtos SET estoque = estoque + ? WHERE codigo = ?", (quantidade, codigo))
    registrar_auditoria(conn, 'REPOSICAO_ESTOQUE', f"+{quantidade} un. em {prod['descricao']} ({codigo})")
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Estoque atualizado com sucesso!'})

@app.route('/api/excluir_produto', methods=['POST'])
@exigir_cargo(['gerente'], api=True)
def excluir_produto():
    dados = request.get_json(silent=True) or {}
    codigo = str(dados.get('codigo', '')).strip()

    conn = db_connect()
    prod = conn.execute("SELECT descricao FROM produtos WHERE codigo = ?", (codigo,)).fetchone()
    if not prod:
        conn.close()
        return jsonify({'erro': 'Produto não encontrado!'}), 404

    conn.execute("DELETE FROM produtos WHERE codigo = ?", (codigo,))
    registrar_auditoria(conn, 'PRODUTO_EXCLUIDO', f"{codigo} - {prod['descricao']}")
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Produto removido com sucesso!'})

# --- APIS DE USUÁRIOS (GERENTE) ---

@app.route('/api/cadastrar_usuario', methods=['POST'])
@exigir_cargo(['gerente'], api=True)
def cadastrar_usuario():
    dados = request.get_json(silent=True) or {}
    nome = re.sub(r'\s+', ' ', str(dados.get('nome', '')).strip())
    usuario = str(dados.get('usuario', '')).strip().lower()
    senha = str(dados.get('senha', '')).strip()
    cargo = str(dados.get('cargo', '')).strip()

    if not re.fullmatch(r'[A-Za-zÀ-ÿ\s]{3,60}', nome):
        return jsonify({'erro': 'Nome inválido! Use apenas letras (mínimo 3 caracteres).'}), 400

    if not re.fullmatch(r'[a-z0-9._]{3,30}', usuario):
        return jsonify({'erro': 'Login inválido! Use de 3 a 30 letras minúsculas, números, ponto ou sublinhado (sem espaços).'}), 400

    if len(senha) < 4 or len(senha) > 50:
        return jsonify({'erro': 'A senha deve ter entre 4 e 50 caracteres!'}), 400

    if cargo not in ['funcionario', 'fiscal', 'gerente']:
        return jsonify({'erro': 'Cargo selecionado inválido!'}), 400

    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO usuarios (nome, usuario, senha, cargo) VALUES (?, ?, ?, ?)",
            (nome, usuario, generate_password_hash(senha), cargo)
        )
        registrar_auditoria(conn, 'USUARIO_CRIADO', f"Novo usuário '{usuario}' com cargo {cargo.upper()}")
        conn.commit()
        return jsonify({'mensagem': 'Usuário criado com sucesso!'})
    except sqlite3.IntegrityError:
        return jsonify({'erro': 'Este login de usuário já está em uso!'}), 400
    finally:
        conn.close()

@app.route('/api/excluir_usuario', methods=['POST'])
@exigir_cargo(['gerente'], api=True)
def excluir_usuario():
    dados = request.get_json(silent=True) or {}
    try:
        user_id = int(dados.get('id', 0))
    except (ValueError, TypeError):
        return jsonify({'erro': 'ID de usuário inválido!'}), 400

    if user_id == session.get('usuario_id'):
        return jsonify({'erro': 'Você não pode excluir a própria conta logada!'}), 400

    conn = db_connect()
    alvo = conn.execute("SELECT nome, usuario, cargo FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if not alvo:
        conn.close()
        return jsonify({'erro': 'Usuário não encontrado!'}), 404

    if alvo['cargo'] == 'gerente':
        qtd_gerentes = conn.execute("SELECT COUNT(*) AS total FROM usuarios WHERE cargo = 'gerente'").fetchone()['total']
        if qtd_gerentes <= 1:
            conn.close()
            return jsonify({'erro': 'Não é possível excluir o único Gerente do sistema!'}), 400

    conn.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    registrar_auditoria(conn, 'USUARIO_EXCLUIDO', f"Removido usuário '{alvo['usuario']}' ({alvo['nome']})")
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Usuário removido!'})

# --- INICIALIZAÇÃO DO SERVIDOR E JANELA NATIVA MAXIMIZADA ---

def esperar_servidor():
    for _ in range(30):
        try:
            urllib.request.urlopen('http://127.0.0.1:5000', timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False

def rodar_flask():
    app.run(host='127.0.0.1', port=5000, use_reloader=False, threaded=True)

if __name__ == '__main__':
    inicializar_banco()
    if TEM_WEBVIEW:
        t = threading.Thread(target=rodar_flask, daemon=True)
        t.start()
        esperar_servidor()
        webview.create_window(
            'GR Pdv - Sistema de Frente de Caixa e Estoque',
            'http://127.0.0.1:5000',
            maximized=True
        )
        if os.path.exists(ICON_PATH):
            webview.start(gui='edgechromium', icon=ICON_PATH)
        else:
            webview.start(gui='edgechromium')
    else:
        print("AVISO: pywebview não encontrado, abrindo no navegador...")
        webbrowser.open('http://127.0.0.1:5000')
        rodar_flask()