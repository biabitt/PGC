from shared.util import hash_para_zq, hash_rotulado_32


def h1(identidade, r_u_ponto) -> int:
    return hash_para_zq("KAUR-H1", identidade, r_u_ponto)


def h2(*valores) -> bytes:
    return hash_rotulado_32("KAUR-H2", *valores)


def kdf(*valores) -> bytes:
    return hash_rotulado_32("KAUR-KDF", *valores)
