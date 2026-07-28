from py_ecc.optimized_bn128 import (
    G1,
    G2,
    add,
    multiply,
    pairing,
    curve_order,
)

from _old.crypto_utils import (
    gerar_aleatorio,
    hash_para_inteiro,
    hash_chave_sessao,
    hash_confirmacao,
    inverso_modular,
)


class SCG:
    """
    Representa a Autoridade Confiável.
    Gera a chave mestra e as chaves privadas das entidades.
    """

    def __init__(self):
        self.s = gerar_aleatorio()
        self.P = G1
        self.Q = G2
        self.Ppub = multiply(self.P, self.s)


class Usuario:
    """
    Representa o usuário do protocolo.
    """

    def __init__(self, identidade):
        self.identidade = identidade
        self.chave_privada = None
        self.chave_sessao = None


class Provedor:
    """
    Representa o Provedor de Serviço.
    """

    def __init__(self, identidade):
        self.identidade = identidade
        self.chave_privada = None
        self.chave_sessao = None
        self.a = None
        self.Z = None


def registrar_usuario(scg, usuario):
    """
    Registro do usuário:
    Si = 1 / (s + H1(IDi)) P
    """
    h_idi = hash_para_inteiro(usuario.identidade)
    denominador = (scg.s + h_idi) % curve_order
    usuario.chave_privada = multiply(scg.P, inverso_modular(denominador))

    return usuario


def registrar_provedor(scg, provedor):
    """
    Registro do provedor:
    Sj = 1 / (s + H1(IDj)) P

    """
    h_idj = hash_para_inteiro(provedor.identidade)
    denominador = (scg.s + h_idj) % curve_order
    provedor.chave_privada = multiply(scg.Q, inverso_modular(denominador))

    return provedor


def provedor_gera_desafio(scg, provedor):
    """
    O provedor escolhe a e calcula:
    Z = e(P,P)^a

    Na py_ecc:
    Z = e(Q,P)^a
    """
    provedor.a = gerar_aleatorio()

    z_base = pairing(scg.Q, scg.P)
    provedor.Z = z_base ** provedor.a

    return provedor.Z


def usuario_gera_mensagem(scg, usuario, provedor, Z):
    """
    O usuário escolhe b, calcula Kij e K2.

    Kij = H2(Z^b)
    K2 = bPpub + H1(IDj)bP
    """
    b = gerar_aleatorio()

    Kij_usuario = hash_chave_sessao(Z ** b)
    usuario.chave_sessao = Kij_usuario

    h_idj = hash_para_inteiro(provedor.identidade)

    parte_1 = multiply(scg.Ppub, b)
    parte_2 = multiply(scg.P, (h_idj * b) % curve_order)

    K2 = add(parte_1, parte_2)

    # C1 ainda será implementado depois.
    C1 = {
        "observacao": "C1 ainda não implementado neste primeiro teste"
    }

    return K2, C1


def provedor_calcula_chave(scg, provedor, K2):
    """
    O provedor reconstrói a chave de sessão usando sua chave privada Sj.

    pairing(Sj, K2)^a = e(Q,P)^(ab)
    """
    valor = pairing(provedor.chave_privada, K2) ** provedor.a
    provedor.chave_sessao = hash_chave_sessao(valor)

    return provedor.chave_sessao


def provedor_gera_confirmacao(provedor, usuario):
    """
    Di = H4(Kij || Z || IDi || IDj)
    """
    Di = hash_confirmacao(
        provedor.chave_sessao,
        provedor.Z,
        usuario.identidade,
        provedor.identidade
    )

    return Di


def usuario_verifica_confirmacao(usuario, provedor, Di_recebido):
    """
    O usuário recalcula Di e compara com o valor recebido.
    """
    Di_calculado = hash_confirmacao(
        usuario.chave_sessao,
        provedor.Z,
        usuario.identidade,
        provedor.identidade
    )

    return Di_calculado == Di_recebido
