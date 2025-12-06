#!/usr/bin/python3

import random
import string
import hashlib

def banner():
    print(
    f"""
        ╔══════════════════════════════════════════════════════════╗
         🔐  PASSWD GENERATOR - CREADOR DE CONTRASEÑAS SEGURAS  🔐
        ╚══════════════════════════════════════════════════════════╝

    💡 Cree contraseñas robustas basadas en longitud y complejidad.

    Requisitos para generar su contraseña:
     - Número de caracteres que tendrá la contraseña.
     - Nivel de complejidad en cuanto a caracteres que componen la contraseña.

    A continuación, le mostramos los niveles de complejidad y la seguridad que ofrecen:
    NIVEL 1. Bajo (Caracteres Numéricos)
    NIVEL 2. Medio (Caracteres Alfabéticos)
    NIVEL 3. Alto (Caracteres Alfanuméricos)
    NIVEL 4. Muy Alto (Caracteres Alfanuméricos + Signos)
    """)
def verificar_acceso():
    # import hashlib
    # from getpass import getpass
    print("\nPARA USAR EL PASSWD GENERATOR, DEBE INTRODUCIR LA CONTRASEÑA.")
    while True:
        try:
            # paswd = getpass("Inserte PASSWD: ")
            paswd = input(" - Inserte PASSWD: ")
            paswd_hash = hashlib.sha256(paswd.encode()).hexdigest()

            if paswd_hash == "dd130a849d7b29e5541b05d2f7f86a4acd4f1ec598c1c9438783f56bc4f0ff80":
                print("✅ LA CONTRASEÑA ES CORRECTA!")
                return True
            else:
                print(f"⚠️ La contraseña es incorrecta\n")

        except ValueError:
            print(f"⚠️ La contraseña es incorrecta\n")
def obtener_longitud():
    while True:
        try:
            longitud = int(input("\n1️⃣ Inserte el número de caracteres para la contraseña: "))
            if longitud <= 0:
                print("\n ⚠️ La longitud debe ser un valor positivo!")

            elif longitud < 8:
                print("\n ⚠️ Para que una contraseña se empiece a considerar 'segura', "
                      "debe superar, al menos, los 8 caracteres.")

                aviso = input("Teniendo en cuenta esto, ¿está seguro de su elección? [SI/NO]: ").upper()
                if aviso in ["SI", "S"]:
                    return longitud
                else:
                    print("🔐 Buena elección. Intente con una longitud mayor.")

            else:
                return longitud
        except ValueError:
            print("⚠️ El valor insertado no es válido.")
def obtener_nivel_de_complejidad():
    while True:
        # print("\nA continuación, le mostramos los niveles de complejidad en cuanto a caracteres:")
        # print("NIVEL 1. Bajo (Caracteres Numéricos)")
        # print("NIVEL 2. Medio (Caracteres Alfabéticos)")
        # print("NIVEL 3. Alto (Caracteres Alfanuméricos)")
        # print("NIVEL 4. Muy Alto (Caracteres Alfanuméricos + Signos)")

        try:
            nivel = int(input("\n2️⃣ Inserte el nivel de complejidad (1-4): "))
            if nivel < 1:
                print("⚠️ El valor mínimo es 1.")
            elif nivel > 4:
                print("⚠️ El valor máximo es 4.")
            else:
                return nivel
        except ValueError:
            print("⚠️ El valor insertado no es válido. Las opciones son del 1 al 4.")
def generar_password(longitud, nivel):
    caracteres = ""

    if nivel == 1:  # Bajo: Solo números
        caracteres = string.digits
    elif nivel == 2:  # Medio: Solo letras
        caracteres = string.ascii_letters
    elif nivel == 3:  # Alto: Letras y números
        caracteres = string.ascii_letters + string.digits
    elif nivel == 4:  # Muy alto: Letras, números y signos
        caracteres = string.ascii_letters + string.digits + string.punctuation

    password = ''.join(random.choice(caracteres) for caracter in range(longitud))
    return password
def startCode():
    verificar_acceso()
    banner()

    continuar = True
    while continuar == True:
        longitud = obtener_longitud()
        nivel = obtener_nivel_de_complejidad()

        passwd = generar_password(longitud, nivel)

        print(f"\n🔐 SU CONTRASEÑA HA SIDO GENERADA CON ÉXITO: \n\t{passwd}\n")
        while True:
            try:
                respuesta = input("\n🔁 ¿Deseas generar otra contraseña? (SI/NO): ").upper()
                if respuesta in ['SI','S','I']:
                    break
                elif respuesta in ['NO','N','O']:
                    continuar = False
                    break
                else:
                    print("Por favor, insere 'si o no'.")
            except ValueError:
                print("Por favor, inserte 'si o no'.")
startCode()
