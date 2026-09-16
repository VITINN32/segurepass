from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import random
import string

app = Flask(__name__)
app.secret_key = "segurepass_chave_secreta_super_segura"

# Configuração do Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///senhas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Tabela de Usuários
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    senhas = db.relationship('SenhaSalva', backref='dono', lazy=True)

# Tabela de Senhas Salvas (vinculada ao usuário)
class SenhaSalva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    servico = db.Column(db.String(100), nullable=False)
    senha = db.Column(db.String(100), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

with app.app_context():
    db.create_all()

@app.route("/", methods=["GET", "POST"])
def home():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    senha = ""
    forca = ""
    
    if request.method == "POST":
        tamanho = int(request.form.get("tamanho", 16))
        SacoDeLetras = string.ascii_letters + string.digits + string.punctuation
        senha = "".join(random.choices(SacoDeLetras, k=tamanho))
        
        if tamanho < 8:
            forca = "Fraca"
        elif tamanho <= 11:
            forca = "Média"
        else:
            forca = "Forte"

    senhas_salvas = SenhaSalva.query.filter_by(usuario_id=session["usuario_id"]).all()
    return render_template("index.html", senha=senha, forca=forca, senhas_salvas=senhas_salvas, usuario=session.get("usuario_nome"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        user = Usuario.query.filter_by(nome=nome).first()

        if user and bcrypt.check_password_hash(user.senha_hash, senha):
            session["usuario_id"] = user.id
            session["usuario_nome"] = user.nome
            return redirect(url_for("home"))
        else:
            flash("Usuário ou senha incorretos.")

    return render_template("login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        if Usuario.query.filter_by(nome=nome).first():
            flash("Este nome de usuário já existe.")
        else:
            hash_senha = bcrypt.generate_password_hash(senha).decode('utf-8')
            novo_usuario = Usuario(nome=nome, senha_hash=hash_senha)
            db.session.add(novo_usuario)
            db.session.commit()
            return redirect(url_for("login"))

    return render_template("cadastro.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/salvar", methods=["POST"])
def salvar_senha():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    servico = request.form.get("servico")
    senha = request.form.get("senha_para_salvar")
    
    if servico and senha:
        nova_senha = SenhaSalva(servico=servico, senha=senha, usuario_id=session["usuario_id"])
        db.session.add(nova_senha)
        db.session.commit()
        
    return redirect(url_for("home"))

@app.route("/deletar/<int:id>")
def deletar_senha(id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    senha_para_deletar = SenhaSalva.query.get_or_404(id)
    if senha_para_deletar.usuario_id == session["usuario_id"]:
        db.session.delete(senha_para_deletar)
        db.session.commit()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)