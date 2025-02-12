#!/bin/bash

#este script lee un fichero del NIST CAVPS de AES, y lo estructura en formato del lenguaje C

#función para poner el string hexadecimal en formato C
function formato_hexadecimal() {
  local input="$1"
  local length=${#input}
  local output=""
  local counter=0

  for ((i=0; i<$length; i+=2)); do
    output+="0x${input:i:2}, "
    counter=$((counter + 1))

    # Añadir un salto de línea después de cada 8 pares
    if ((counter % 8 == 0)); then
      output+="\n"
    fi
  done

  # Eliminar la última coma y espacio adicional o salto de línea
  output=${output%, }
  output=${output%\\n}
  
  echo -e "$output"  # Usamos -e para que se interpreten las secuencias de escape
}
#funcion para contar la longitud de el plaintext/ciphertext
function contar_pares_hex() {
  local input="$1"
  local length=${#input}
  local num_pares=$((length / 2))
  echo "$num_pares"
}

echo "introduce el nombre del fichero a leer"
read -r fichero_aes

echo "introduce el nombre del fichero dónde escribir los tests"
read -r testsC_aes

#leemos el fichero de selftests de AES que vamos a pasar a formato C
if [ -e "$fichero_aes" ]; then
	echo "fichero de tests de AES leído correctamente"
else 
	echo "el fichero no existe!"
	exit 1
fi

echo "introduce el nombre de la función de encrypt compare"
read -r ec_funcion
echo "introduce el nombre de la función de decrypt compare"
read -r dc_funcion
echo "introduce el número a partir del cual contar los tests"
read -r num_funcion
#eliminamos espacios en blanco
num_funcion=$(echo "$num_funcion" | tr -d '[:space:]')
#variable para diferenciar entre encrypt y decrypt
enc_dec="0"
numero_test=$((num_funcion - 1))

while read -r line; do
	primera_palabra=$(echo "$line" | cut -d' ' -f1)	
	tercera_palabra=$(echo "$line" | cut -d' ' -f3)
	# Eliminar posibles espacios en blanco adicionales
    primera_palabra=$(echo "$primera_palabra" | tr -d '[:space:]')
    tercera_palabra=$(echo "$tercera_palabra" | tr -d '[:space:]')
	if [ "$primera_palabra" == "COUNT" ]; then
		numero_test=$((numero_test + 1))
		echo "//Testing AES OFB number $numero_test" >> $testsC_aes
	elif [ "$primera_palabra" == "KEY" ]; then
		key=$(formato_hexadecimal "$tercera_palabra")
		echo "unsigned char key$numero_test[] = {" >> $testsC_aes
		echo -e "$key \n};" >> $testsC_aes
	elif [ "$primera_palabra" == "IV" ]; then
		iv=$(formato_hexadecimal "$tercera_palabra")
		echo "unsigned char iv$numero_test[] = {" >> $testsC_aes
		echo -e "$iv \n};" >> $testsC_aes

	elif [ "$primera_palabra" == "PLAINTEXT" ]; then
		if [ $enc_dec == "1" ]; then
			len=$(contar_pares_hex "$tercera_palabra")
			echo "unsigned int len$numero_test = $len;" >> $testsC_aes
		fi
		plaintext=$(formato_hexadecimal "$tercera_palabra")
		echo "unsigned char plaintext$numero_test[] = {" >> $testsC_aes
		echo -e "$plaintext \n};" >> $testsC_aes
		#if is end of test, call the compare function
		if [ $enc_dec == '2' ]; then
			echo "if($dc_funcion(ciphertext$numero_test, len$numero_test, iv$numero_test, key$numero_test, plaintext$numero_test ) == 0) verified = 0;" >> $testsC_aes
			echo -e "\n" >> $testsC_aes
		fi
	elif [ "$primera_palabra" == "CIPHERTEXT" ]; then
		if [ $enc_dec == "2" ]; then
			len=$(contar_pares_hex "$tercera_palabra")
			echo "unsigned int len$numero_test = $len;" >> $testsC_aes
		fi
		ciphertext=$(formato_hexadecimal "$tercera_palabra")
		echo "unsigned char ciphertext$numero_test[] = {" >> $testsC_aes
		echo -e "$ciphertext \n};" >> $testsC_aes
		#if end of test, call the compare function
		if [ $enc_dec == '1' ]; then
			echo "if($ec_funcion(plaintext$numero_test, len$numero_test, iv$numero_test, key$numero_test, ciphertext$numero_test ) == 0) verified = 0;" >> $testsC_aes
			echo -e "\n" >> $testsC_aes
		fi

	#ahora los casos para alternar entre los tests de cifrar y descifrar
	elif [ "$primera_palabra" == "[ENCRYPT]" ]; then
		enc_dec="1"
	elif [ "$primera_palabra" == "[DECRYPT]" ]; then
		enc_dec="2"
	else
		if [ ${#line} -gt 2 ]; then
			echo "//$line" >> $testsC_aes
		fi
	fi
done < "$fichero_aes"






