import pytest

from guardian.validators import cuit_valido, dni_plausible, email_valido, luhn_valid


def test_luhn_valido_con_y_sin_separadores():
    assert luhn_valid("4539148803436467")
    assert luhn_valid("4539 1488 0343 6467")
    assert luhn_valid("4539-1488-0343-6467")


def test_luhn_invalido_un_digito_cambiado():
    assert not luhn_valid("4539148803436468")


def test_luhn_rechaza_letras_y_largos_absurdos():
    assert not luhn_valid("4539 1488 0343 646A")
    assert not luhn_valid("1234")
    assert not luhn_valid("")


def test_cuit_valido_con_y_sin_guiones():
    assert cuit_valido("20-12345678-6")
    assert cuit_valido("20123456786")


def test_cuit_dígito_verificador_incorrecto():
    assert not cuit_valido("20-12345678-7")


def test_cuit_prefijo_invalido():
    assert not cuit_valido("10-12345678-6")


def test_cuit_con_resto_10_nunca_es_valido():
    # Busca una base cuyo dígito calculado daría 10: ese CUIT no puede existir.
    for n in range(100_000_000):
        base = f"20{n:08d}"
        suma = sum(int(d) * w for d, w in zip(base, (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)))
        if 11 - suma % 11 == 10:
            for digito in range(10):
                assert not cuit_valido(base + str(digito))
            return
    pytest.fail("no se encontró una base con resto 10")


@pytest.mark.parametrize("texto", ["12.345.678", "12345678", "1.234.567", "1234567"])
def test_dni_plausible(texto):
    assert dni_plausible(texto)


@pytest.mark.parametrize("texto", ["1234", "123456789", "100000000", "0.000.001", "12a45678"])
def test_dni_no_plausible(texto):
    assert not dni_plausible(texto)


def test_email_dominio_real_valido():
    assert email_valido("maria.gomez@estudio-lopez.com.ar")


@pytest.mark.parametrize("email", ["pruebas@example.com", "x@sub.example.com", "y@EXAMPLE.ORG", "z@test"])
def test_email_dominio_reservado_no_es_pii(email):
    assert not email_valido(email)
