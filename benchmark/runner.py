import time

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

from puf.credential_protector import CredentialProtector
from puf.fuzzy_extractor import FuzzyExtractorSimples
from puf.simulacao import PUFConfig, SimulatedPUF

from benchmark.base import ResultadoComponente, ResultadoPar

_agora_ns = time.perf_counter_ns


def _cronometrar(funcao, *args):
    """Executa funcao(*args) e devolve quanto tempo levou, em nanossegundos."""
    inicio = _agora_ns()
    funcao(*args)
    return _agora_ns() - inicio


class _Cronometro:
    """Acumula, por lado, o tempo das chamadas de uma troca de autenticação."""

    def __init__(self) -> None:
        self.cliente_ns = 0
        self.servidor_ns = 0

    def cliente(self, funcao, *args):
        inicio = _agora_ns()
        valor = funcao(*args)
        self.cliente_ns += _agora_ns() - inicio
        return valor

    def servidor(self, funcao, *args):
        inicio = _agora_ns()
        valor = funcao(*args)
        self.servidor_ns += _agora_ns() - inicio
        return valor


class BenchmarkRunner:
    def __init__(self, config: PUFConfig | None = None) -> None:
        self._config = config or PUFConfig()

    # --- núcleo pareado -----------------------------------------------------------

    def _medir_versao(self, versao, identidade, cenario, criar, autenticar, apos_registro):
        """Roda o protocolo inteiro para uma versão (original ou puf) e devolve os tempos:
        registro, preparo, auth (ponta a ponta), auth do cliente, auth do servidor."""
        cliente, registro = criar(versao, identidade, cenario)
        registro_ns = _cronometrar(cliente.receber_registro, registro)
        if apos_registro:
            apos_registro(cliente, cenario, registro)          # lado servidor, fora do tempo
        preparar = getattr(cliente, "preparar_autenticacao", None)
        preparo_ns = _cronometrar(preparar) if preparar else 0
        inicio = _agora_ns()                                   # ponta a ponta, medição independente
        auth_cliente_ns, auth_servidor_ns = autenticar(cliente, cenario, versao)
        auth_ns = _agora_ns() - inicio
        if hasattr(cliente, "finalizar_sessao"):
            cliente.finalizar_sessao()
        return registro_ns, preparo_ns, auth_ns, auth_cliente_ns, auth_servidor_ns

    def _medir(self, nome, rodadas, *, preparar, criar, autenticar, apos_registro=None):
        """Laço pareado: em cada rodada mede as duas versões, em ordem alternada."""
        cenario = preparar()
        resultados = []
        for rodada in range(rodadas):
            ordem = ("original", "puf") if rodada % 2 == 0 else ("puf", "original")
            tempos = {versao: self._medir_versao(versao, f"cliente{rodada}", cenario,
                                                 criar, autenticar, apos_registro)
                      for versao in ordem}
            registro_orig, preparo_orig, auth_orig, cli_orig, srv_orig = tempos["original"]
            registro_puf, preparo_puf, auth_puf, cli_puf, srv_puf = tempos["puf"]
            sessao_orig = preparo_orig + auth_orig
            sessao_puf = preparo_puf + auth_puf
            resultados.append(ResultadoPar(
                nome, rodada,
                registro_orig, registro_puf, preparo_orig, preparo_puf, auth_orig, auth_puf,
                sessao_orig, sessao_puf, sessao_puf - sessao_orig,
                cli_orig, srv_orig, cli_puf, srv_puf,
            ))
        return resultados

    @staticmethod
    def _checar(sucesso: bool, nome: str, versao: str) -> None:
        if not sucesso:
            raise RuntimeError(f"Autenticação {nome} falhou ({versao}).")

    # --- Tsai-Lo (base) e Irshad (estudo de caso principal): mesmo fluxo de 4 msgs ---

    def _medir_fluxo_tsailo(self, nome, rodadas, classe_servidor, criar_cliente):
        def preparar():
            sgc = SGC()
            parametros = sgc.configurar_sistema()
            servidor = classe_servidor("servidor01")
            servidor.receber_parametros(parametros)
            servidor.receber_registro(sgc.registrar_servidor("servidor01"))
            return {"sgc": sgc, "parametros": parametros, "servidor": servidor}

        def criar(versao, identidade, cenario):
            identidade = f"{identidade}-{versao[0]}"   # "-o" / "-p": mesmo tamanho nas duas versões
            cliente = criar_cliente(versao, identidade)
            cliente.receber_parametros(cenario["parametros"])
            return cliente, cenario["sgc"].registrar_cliente(identidade)

        def autenticar(cliente, cenario, versao):
            servidor = cenario["servidor"]
            t = _Cronometro()
            solicitacao = t.cliente(cliente.criar_solicitacao, servidor.identidade)
            desafio = t.servidor(servidor.gerar_desafio, solicitacao)
            resposta = t.cliente(cliente.responder_desafio, desafio)
            resultado = t.servidor(servidor.autenticar_cliente, resposta)
            sucesso = resultado.autenticado and t.cliente(cliente.autenticar_servidor, resultado.confirmacao)
            self._checar(sucesso and cliente.chave_sessao == servidor.chave_sessao, nome, versao)
            return t.cliente_ns, t.servidor_ns

        return self._medir(nome, rodadas, preparar=preparar, criar=criar, autenticar=autenticar)

    def medir_tsailo(self, rodadas):
        return self._medir_fluxo_tsailo("tsailo", rodadas, ServidorTsaiLo, lambda versao, identidade: (
            ClienteTsaiLo(identidade, "senha123") if versao == "original"
            else ClienteTsaiLoPUF(identidade, config=self._config)))

    def medir_irshad(self, rodadas):
        return self._medir_fluxo_tsailo("irshad", rodadas, ServidorIrshad, lambda versao, identidade: (
            ClienteIrshad(identidade, "senha123", "digital01") if versao == "original"
            else ClienteIrshadPUF(identidade, config=self._config)))

    # --- Jia ----------------------------------------------------------------------

    def medir_jia(self, rodadas):
        def preparar():
            rc = CentroRegistroJia()
            parametros = rc.configurar_sistema()
            servidor = ServidorMECJia("servidorMEC01")
            servidor.receber_parametros(parametros)
            servidor.receber_registro(rc.registrar_servidor("servidorMEC01"))
            return {"rc": rc, "parametros": parametros, "servidor": servidor}

        def criar(versao, identidade, cenario):
            identidade = f"{identidade}-{versao[0]}"   # "-o" / "-p": mesmo tamanho nas duas versões
            cliente = (UsuarioJia(identidade) if versao == "original"
                       else UsuarioJiaPUF(identidade, config=self._config))
            cliente.receber_parametros(cenario["parametros"])
            return cliente, cenario["rc"].registrar_usuario(identidade)

        def autenticar(cliente, cenario, versao):
            servidor = cenario["servidor"]
            t = _Cronometro()
            mensagem = t.cliente(cliente.criar_mensagem_autenticacao, servidor.identidade)
            resultado = t.servidor(servidor.autenticar_usuario, mensagem)
            sucesso = resultado.autenticado and t.cliente(cliente.verificar_resposta, resultado.resposta)
            self._checar(sucesso and cliente.chave_sessao == servidor.chave_sessao, "Jia", versao)
            return t.cliente_ns, t.servidor_ns

        return self._medir("jia", rodadas, preparar=preparar, criar=criar, autenticar=autenticar)

    # --- Kaur ---------------------------------------------------------------------

    def medir_kaur(self, rodadas):
        def preparar():
            rc = CentroRegistroKaur()
            parametros = rc.configurar_sistema()
            servidor = ServidorMECKaur("servidorMEC01")
            servidor.receber_parametros(parametros)
            reg = rc.registrar_servidor("servidorMEC01")
            servidor.receber_registro(reg)
            dados = DadosPublicosServidor(sid_ms=reg.sid_ms, p_ms=reg.p_ms, r_ms_ponto=reg.r_ms_ponto)
            return {"rc": rc, "parametros": parametros, "servidor": servidor, "dados_servidor": dados}

        def criar(versao, identidade, cenario):
            identidade = f"{identidade}-{versao[0]}"   # "-o" / "-p": mesmo tamanho nas duas versões
            cliente = (UsuarioKaur(identidade) if versao == "original"
                       else UsuarioKaurPUF(identidade, config=self._config))
            cliente.receber_parametros(cenario["parametros"])
            return cliente, cenario["rc"].registrar_usuario(identidade)

        def apos_registro(cliente, cenario, registro):
            # provisionamento do lado servidor (não é custo do cliente)
            cenario["servidor"].registrar_usuario_publico(DadosPublicosUsuario(
                sid_u=registro.sid_u, r_u_ponto=registro.r_u_ponto, p_u=registro.p_u))
            cliente.definir_servidor(cenario["dados_servidor"])

        def autenticar(cliente, cenario, versao):
            servidor = cenario["servidor"]
            t = _Cronometro()
            mensagem = t.cliente(cliente.criar_mensagem_autenticacao)
            resultado = t.servidor(servidor.autenticar_usuario, mensagem)
            confirmacao = t.cliente(cliente.verificar_resposta, resultado.resposta)
            sucesso = (resultado.autenticado and confirmacao is not None
                       and t.servidor(servidor.verificar_confirmacao, confirmacao))
            self._checar(sucesso and cliente.chave_sessao == servidor.chave_sessao, "Kaur", versao)
            return t.cliente_ns, t.servidor_ns

        return self._medir("kaur", rodadas, preparar=preparar, criar=criar,
                           autenticar=autenticar, apos_registro=apos_registro)

    # --- decomposição da camada (--detalhado) --------------------------------------

    def medir_componentes(self, rodadas, pid="IRSHAD", tamanho_credencial=128):
        puf = SimulatedPUF(self._config)
        fuzzy = FuzzyExtractorSimples(self._config.tamanho_chave, self._config.repeticoes)
        protector = CredentialProtector(puf, fuzzy, pid, "cliente01")
        segredo = b"\x00" * tamanho_credencial
        resultados = []

        for rodada in range(rodadas):
            puf_ns = _cronometrar(puf.avaliar)
            resposta = puf.avaliar()
            inicio = _agora_ns(); chave, helper = fuzzy.gen(resposta); gen_ns = _agora_ns() - inicio
            ruidosa = puf.avaliar()  # fora do cronômetro: isola só o custo de Rep
            rep_ns = _cronometrar(fuzzy.rep, ruidosa, helper)
            mask_ns = _cronometrar(protector._mascara, chave, "KEY", tamanho_credencial)
            protect_ns = _cronometrar(protector.registrar, {"KEY": segredo})
            recover_ns = _cronometrar(protector.recuperar)

            resultados += [ResultadoComponente(operacao, rodada, tempo_ns) for operacao, tempo_ns in (
                ("puf", puf_ns), ("gen", gen_ns), ("rep", rep_ns),
                ("mask", mask_ns), ("protect", protect_ns), ("recover", recover_ns))]
        return resultados
