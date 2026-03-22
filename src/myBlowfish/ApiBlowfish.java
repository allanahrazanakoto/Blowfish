/********************************************************************
 * API Blowfish pour le chiffrement où déchifrement de tableau d'octets
 * ou de chaine de caractères
 * Auteur:		Didier Samfat
 * Date:		27 Mar 2021
 * Version:		1.0 : Traitement des byte[]
 * Version 		2.0 : Traitement des String
 ********************************************************************/
package myBlowfish;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
public class ApiBlowfish {

	private static final String ALGORITHM = "Blowfish";

	/**
	 * Génére aléatoirement unen clé cryptographique Blowfish
	 * @return la clé ainsi crée
	 * @throws Exception
	 */
	public static Key generateKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
		keyGen.init(256);
		Key cleBlowfish = keyGen.generateKey();
		return cleBlowfish;
	}

	/**
	 * Méthode qui peut Chiffrer n'importe qyu'elle donnée et le met en format
	 * octets son appel dans une autre classe se fait par ApiBlowfish.generateKey()
	 * @param textClair: tout type de donnés pouvant être codé em obctets
	 * @param clef:      la clé de chifremment à utiliser
	 * @return : retourne le cryptage sous forme d'octets
	 * @throws Exception
	 */
	public static byte[] encryptInByte(byte[] textClair, Key clef) throws Exception {
		Cipher chiffre = Cipher.getInstance(ALGORITHM);
		chiffre.init(Cipher.ENCRYPT_MODE, clef);
		return chiffre.doFinal(textClair);
	}

	/**
	 * Méthode qui déchiffre les donnée déjà chiffrées son appel dans une autre
	 * classe se fait par ApiBlowfish.decryptInByte(..)
	 * @param textChiffre: les octets à déchiffrer
	 * @param clef         doit être la même clé utilisée pour chiffrer
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptInByte(byte[] textChiffre, Key clef) throws Exception {
		Cipher dechiffre = Cipher.getInstance(ALGORITHM);
		dechiffre.init(Cipher.DECRYPT_MODE, clef);
		byte[] textDechiffre = dechiffre.doFinal(textChiffre);
		return textDechiffre;
	}

	/**
	 * Méthode qui peut Chiffrer uniquement une chaîne de caractères son appel dans
	 * une autre classe se fait par ApiBlowfish.encryptInString(..)
	 * @param textClair
	 * @param clef
	 * @return sous un format encodé affichable dans la console
	 * @throws Exception
	 */
	public static String encryptInString(String textClair, Key clef) throws Exception {
		byte[] chiffre = textClair.getBytes();
		chiffre = encryptInByte(chiffre, clef);
		return Base64.getEncoder().encodeToString(chiffre);
	}

	/**
	 * Méthode qui peut Chiffrer uniquement une chaîne de caractères en utiliant la
	 * même clé que pour chiffrer on l'appel par ApiBlowfish.decryptInString(..)
	 * @param textChiffre
	 * @param clef        : doit être crée préalablement
	 * @return la chaine chiffrée
	 * @throws Exception
	 */
	public static String decryptInString(String textChiffre, Key clef) throws Exception {
		byte[] dechiffre = Base64.getDecoder().decode(textChiffre);
		dechiffre = decryptInByte(dechiffre, clef);
		return new String(dechiffre);
	}
}
