/**********************************************************************************
 * API: APIFileCipher - Suppose que la clé blowfish a déjà été généré
 * Description: Utilise ApiBlowfish pour le chiffrement et déchiffrement de fichier
 * Auteur: Didier Samfat
 * Date: 28 Mar 2021
 * Version: 1.0
 *********************************************************************************/

package myBlowfish;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.util.Base64;

public class ApiFileCipher {

    /**
     * Méthode qui lit un fichier est retourne ce qu'il a lu
     * @param nomFichier: le fichier à lire
     * @return : la chaîne lue
     */
    static String read(String nomFichier) {
        try {
            File inFile = new File(nomFichier);
            try (FileInputStream inputStream = new FileInputStream(inFile)) {
                byte[] inBytes = new byte[(int) inFile.length()];
                inputStream.read(inBytes);
                return new String(inBytes);
            }
        } catch (FileNotFoundException e) {
            // fichier non trouvé
        } catch (IOException e) {
            // erreur lecture
        }
        return null;
    }

    /**
     * Méthode qui chiffre un fichier donné avec une clé blowfish
     * @param nomFichier : fichier qui doit être chiffré
     * @param clef : doit être généré au préalable
     * @return : le texte chiffré encodé en Base64
     * @throws Exception
     */
    static String encrypt(String nomFichier, Key clef) throws Exception {
        try {
            File inFile = new File(nomFichier);
            try (FileInputStream inputStream = new FileInputStream(inFile)) {
                byte[] inBytes = new byte[(int) inFile.length()];
                inputStream.read(inBytes);

                String fichierCrypte = nomFichier + ".cryp";
                File outFile = new File(fichierCrypte);
                try (FileOutputStream outputStream = new FileOutputStream(outFile)) {
                    byte[] texteChiffre = ApiBlowfish.encryptInByte(inBytes, clef);
                    outputStream.write(texteChiffre);
                    return Base64.getEncoder().encodeToString(texteChiffre);
                }
            }
        } catch (FileNotFoundException e) {
            // fichier non trouvé
        } catch (IOException e) {
            // erreur lecture/écriture
        }
        return null;
    }

    static String decrypt(String nomFichier, Key clef) throws Exception {
        try {
            File inFile = new File(nomFichier);
            try (FileInputStream inputStream = new FileInputStream(inFile)) {
                byte[] inBytes = new byte[(int) inFile.length()];
                inputStream.read(inBytes);
                byte[] texteDechiffre = ApiBlowfish.decryptInByte(inBytes, clef);
                return new String(texteDechiffre);
            }
        } catch (FileNotFoundException e) {
            // fichier non trouvé
        } catch (IOException e) {
            // erreur lecture
        }
        return null;
    }
}
