import sys

from protocolo.cliente import Cliente as ClienteTsaiLo
from protocolo.servidor import Servidor as ServidorTsaiLo
from protocolo.sgc import SGC
from protocolo_irshad.cliente import ClienteIrshad
from protocolo_irshad.cliente_puf import ClienteIrshadPUF
from protocolo_irshad.servidor import ServidorIrshad
from protocolo_jia.cliente import Usuario as UsuarioJia
from protocolo_jia.cliente_puf import UsuarioPUF as UsuarioJiaPUF
from protocolo_jia.rc import CentroRegistro as CentroRegistroJia
from protocolo_jia.servidor import ServidorMEC as ServidorMECJia
from protocolo_kaur.cliente import Usuario as UsuarioKaur
from protocolo_kaur.cliente_puf import UsuarioPUF as UsuarioKaurPUF
from protocolo_kaur.rc import CentroRegistro as CentroRegistroKaur
from protocolo_kaur.servidor import ServidorMEC as ServidorMECKaur
from protocolo_kaur.tipos import DadosPublicosServidor, DadosPublicosUsuario
from protocolo_tsailo.cliente_puf import ClienteTsaiLoPUF

from shared.util import exibir_secao, flag_puf


def _relatar(cliente_ok, servidor_ok, cliente, servidor, extra=None) -> None:
    print("Cliente autenticado pelo servidor:", cliente_ok)
    print("Servidor autenticado pelo cliente:", servidor_ok)
    if extra:
        print(extra)
    iguais = cliente.chave_sessao == servidor.chave_sessao
    print("Chaves de sessão iguais:", iguais)
    if iguais:
        print("Chave de sessão:", cliente.chave_sessao.hex())


def _fluxo_tsailo(cliente, servidor, sgc, parametros) -> None:
    cliente.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    cliente.receber_registro(sgc.registrar_cliente(cliente.identidade))
    servidor.receber_registro(sgc.registrar_servidor(servidor.identidade))

    if hasattr(cliente, "preparar_autenticacao"):
        cliente.preparar_autenticacao()
    desafio = servidor.gerar_desafio(cliente.criar_solicitacao(servidor.identidade))
    resultado = servidor.autenticar_cliente(cliente.responder_desafio(desafio))
    if not resultado.autenticado:
        print("O servidor rejeitou o cliente:", resultado.motivo)
        return
    _relatar(True, cliente.autenticar_servidor(resultado.confirmacao), cliente, servidor)
    if hasattr(cliente, "finalizar_sessao"):
        cliente.finalizar_sessao()


def tsailo(com_puf: bool) -> None:
    sgc = SGC()
    parametros = sgc.configurar_sistema()
    cliente = ClienteTsaiLoPUF("cliente01") if com_puf else ClienteTsaiLo("cliente01", "senha123")
    _fluxo_tsailo(cliente, ServidorTsaiLo("servidor01"), sgc, parametros)


def irshad(com_puf: bool) -> None:
    sgc = SGC()
    parametros = sgc.configurar_sistema()
    cliente = (ClienteIrshadPUF("cliente01") if com_puf
               else ClienteIrshad("cliente01", "senha123", "digital01"))
    _fluxo_tsailo(cliente, ServidorIrshad("servidor01"), sgc, parametros)


def jia(com_puf: bool) -> None:
    rc = CentroRegistroJia()
    parametros = rc.configurar_sistema()
    usuario = UsuarioJiaPUF("usuario01") if com_puf else UsuarioJia("usuario01")
    servidor = ServidorMECJia("servidorMEC01")
    usuario.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    usuario.receber_registro(rc.registrar_usuario(usuario.identidade))
    servidor.receber_registro(rc.registrar_servidor(servidor.identidade))

    if com_puf:
        usuario.preparar_autenticacao()
    resultado = servidor.autenticar_usuario(usuario.criar_mensagem_autenticacao(servidor.identidade))
    if not resultado.autenticado:
        print("O servidor rejeitou o usuário:", resultado.motivo)
        return
    _relatar(True, usuario.verificar_resposta(resultado.resposta), usuario, servidor)
    if com_puf:
        usuario.finalizar_sessao()


def kaur(com_puf: bool) -> None:
    rc = CentroRegistroKaur()
    parametros = rc.configurar_sistema()
    usuario = UsuarioKaurPUF("usuario01") if com_puf else UsuarioKaur("usuario01")
    servidor = ServidorMECKaur("servidorMEC01")
    reg_u = rc.registrar_usuario(usuario.identidade)
    reg_s = rc.registrar_servidor(servidor.identidade)
    usuario.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    usuario.receber_registro(reg_u)
    servidor.receber_registro(reg_s)
    servidor.registrar_usuario_publico(DadosPublicosUsuario(reg_u.sid_u, reg_u.r_u_ponto, reg_u.p_u))
    usuario.definir_servidor(DadosPublicosServidor(reg_s.sid_ms, reg_s.p_ms, reg_s.r_ms_ponto))

    if com_puf:
        usuario.preparar_autenticacao()
    resultado = servidor.autenticar_usuario(usuario.criar_mensagem_autenticacao())
    if not resultado.autenticado:
        print("O servidor rejeitou o usuário:", resultado.motivo)
        return
    confirmacao = usuario.verificar_resposta(resultado.resposta)
    if confirmacao is None:
        print("O usuário rejeitou o servidor (Auth_ms inválido).")
        return
    confirmou = servidor.verificar_confirmacao(confirmacao)
    _relatar(True, True, usuario, servidor, f"Servidor confirmou o usuário (Auth_u): {confirmou}")
    if com_puf:
        usuario.finalizar_sessao()


PROTOCOLOS = {"tsailo": tsailo, "irshad": irshad, "jia": jia, "kaur": kaur}


def main() -> None:
    nomes = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(nomes) != 1 or nomes[0] not in PROTOCOLOS:
        print(__doc__)
        sys.exit(1)
    com_puf = flag_puf()
    exibir_secao(f"{nomes[0].upper()} ET AL. - {'COM CAMADA PUF' if com_puf else 'ORIGINAL (sem PUF)'}")
    try:
        PROTOCOLOS[nomes[0]](com_puf)
    except Exception as erro:  # noqa: BLE001
        print("Erro:", type(erro).__name__, "-", erro)


if __name__ == "__main__":
    main()
