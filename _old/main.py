from _old.protocol import (
    SCG,
    Usuario,
    Provedor,
    registrar_usuario,
    registrar_provedor,
    provedor_gera_desafio,
    usuario_gera_mensagem,
    provedor_calcula_chave,
    provedor_gera_confirmacao,
    usuario_verifica_confirmacao,
)


def main():
    print("=== SIMULAÇÃO DO PROTOCOLO DE TSAI E LO ===")

    print("\n[1] Setup do sistema")
    scg = SCG()
    print("SCG gerou a chave mestra s.")
    print("SCG calculou a chave pública Ppub = sP.")

    print("\n[2] Criação das entidades")
    usuario = Usuario("usuario01")
    provedor = Provedor("provedor01")
    print("Usuário criado com identidade:", usuario.identidade)
    print("Provedor criado com identidade:", provedor.identidade)

    print("\n[3] Registro do usuário")
    registrar_usuario(scg, usuario)
    print("Chave privada do usuário Si calculada.")

    print("\n[4] Registro do provedor")
    registrar_provedor(scg, provedor)
    print("Chave privada do provedor Sj calculada.")

    print("\n[5] Provedor gera desafio")
    Z = provedor_gera_desafio(scg, provedor)
    print("Provedor calculou Z = e(P,P)^a.")
    print("Provedor enviou Z ao usuário.")

    print("\n[6] Usuário gera mensagem de autenticação")
    K2, C1 = usuario_gera_mensagem(scg, usuario, provedor, Z)
    print("Usuário calculou Kij.")
    print("Usuário calculou K2.")
    print("Usuário enviou (K2, C1) ao provedor.")

    print("\n[7] Provedor calcula chave de sessão")
    provedor_calcula_chave(scg, provedor, K2)
    print("Provedor calculou Kij.")

    print("\n[8] Comparação das chaves de sessão")
    print("Kij do usuário: ", usuario.chave_sessao)
    print("Kij do provedor:", provedor.chave_sessao)

    if usuario.chave_sessao == provedor.chave_sessao:
        print("SUCESSO: usuário e provedor chegaram à mesma chave de sessão.")
    else:
        print("ERRO: as chaves de sessão ficaram diferentes.")

    print("\n[9] Provedor gera confirmação Di")
    Di = provedor_gera_confirmacao(provedor, usuario)
    print("Provedor enviou Di ao usuário.")

    print("\n[10] Usuário verifica Di")
    valido = usuario_verifica_confirmacao(usuario, provedor, Di)

    if valido:
        print("SUCESSO: usuário confirmou a autenticidade do provedor.")
    else:
        print("ERRO: confirmação Di inválida.")

    print("\n=== FIM DA SIMULAÇÃO ===")


if __name__ == "__main__":
    main()
