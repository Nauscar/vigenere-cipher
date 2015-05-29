#include "vigenere.h"

Vigenere::Vigenere()
{

}

void Vigenere::Import(QString* filename)
{
    QFile file(*filename);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        qDebug() << QString("Unable to open file \"%1\"").arg(*filename) << endl;
        return;
    }
    cipher = file.readAll();
    file.close();
    qDebug() << QString("A cipher of size %1 was imported successfully").arg(cipher.length()) << endl;
    return;
}

QByteArray* Vigenere::GetCipher()
{
    return &cipher;
}

void Vigenere::Solve(QString* destination)
{
    quint32 keyLength = probableKeyLength(); //A list of most probable key lengths is returned.
    QByteArray key = QByteArray();
    findKey(&key, keyLength);
    QByteArray decrypted = QByteArray();
    Decrypt(&cipher, &key, &decrypted);
    //qDebug() << "Plain Text:";
    //qDebug() << QString(decrypted);

    qDebug() << QString("Key found: \"%1\"").arg(QString(key));

    QFile file(*destination);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)){
        qDebug() << QString("Unable to open file \"%1\"").arg(*destination);
    }
    file.write(decrypted);
    file.close();
    qDebug() << QString("Plaintext outputted to \"%1\"").arg(*destination) << endl;
}

quint32 Vigenere::probableKeyLength()
{
    QList<qreal> averageICs;
    quint32 length;
    QList<quint32> verify;
    for(length = 2; length < cipher.length(); length++){
        QList<QByteArray> caesars;
        setCaesars(&caesars, length);

        qreal averageIC = 0;
        foreach(QByteArray caeser, caesars){
            averageIC += indexOfCoincidence(&caeser);
        }
        averageIC /= caesars.length();

        if(averageICs.length() > 1){
        qreal previous = averageICs.at(averageICs.length() - 2);
        qreal reference = averageICs.at(averageICs.length() - 1);
            if(reference > averageIC && reference > previous){
                if(verify.length() != 0){
                    foreach(quint32 entry, verify){
                        if((length - 1) % entry == 0) {
                            qDebug() << endl << QString("Repetition discovered! Probable key length is %1").arg(entry) << endl;
                            return entry;
                        }
                    }
                }
                verify.append(length - 1);
            }
        }

        averageICs.append(averageIC);
        qDebug() << QString("Key Size %1, \t Average IC %2").arg(length).arg(averageIC);
    }
    return 0;
}

void Vigenere::setCaesars(QList<QByteArray>* caesars, quint32 length)
{
    for(quint32 c = 0; c < length; c++){
        caesars->append(QByteArray());
    }
    for(quint32 index = 0; index < cipher.length(); index++){
        (*caesars)[index % length].append(cipher.at(index));
    }
}

qreal Vigenere::indexOfCoincidence(QByteArray* caesar)
{
    quint32 c = 26; //A constant of 26 is used due to English.
    quint32 length = caesar->length();
    quint32 numerator;
    for(quint32 letter = 97; letter <= 122; letter++){
        QChar ch = QChar(letter);
        quint32 count = caesar->count(ch.toLatin1());
        numerator += count * (count - 1);
    }
    return (qreal)c * numerator / (length * (length - 1));
}

void Vigenere::findKey(QByteArray* key, quint32 keyLength)
{
    QList<QByteArray> caesars;
    setCaesars(&caesars, keyLength);
    qreal letterProbabilities[26] = {
                                                          /*a*/ 0.08167,
                                                          /*b*/ 0.01492,
                                                          /*c*/ 0.02782,
                                                          /*d*/ 0.04253,
                                                          /*e*/ 0.12702,
                                                          /*f*/ 0.02228,
                                                          /*g*/ 0.02015,
                                                          /*h*/ 0.06094,
                                                          /*i*/ 0.06966,
                                                          /*j*/ 0.00153,
                                                          /*k*/ 0.00772,
                                                          /*l*/ 0.04025,
                                                          /*m*/ 0.02406,
                                                          /*n*/ 0.06749,
                                                          /*o*/ 0.07507,
                                                          /*p*/ 0.01929,
                                                          /*q*/ 0.00095,
                                                          /*r*/ 0.05987,
                                                          /*s*/ 0.06327,
                                                          /*t*/ 0.09056,
                                                          /*u*/ 0.02758,
                                                          /*v*/ 0.00978,
                                                          /*w*/ 0.02361,
                                                          /*x*/ 0.00150,
                                                          /*y*/ 0.01974,
                                                          /*z*/ 0.00074
                                                      };
    /*qreal sum = 0;
    for(int c = 0; c < sizeof(letterProbabilities) / sizeof(*letterProbabilities); c++){
        sum += letterProbabilities[c];
    }
    qDebug() << QString("The sum of the probability set is %1").arg(sum);*/

    foreach(QByteArray caesar, caesars){
        QList<qreal> chiSquareds;
        for(quint32 shift = 0; shift < 26; shift++){
            QByteArray tmpCaesar = QByteArray();
            QChar keyChar = QChar(shift + 97);
            QByteArray key = QByteArray();
            key.append(keyChar);
            Decrypt(&caesar, &key, &tmpCaesar);

            qreal chiSquared = 0;
            for(quint32 letter = 97; letter <= 122; letter++){
                QChar ch = QChar(letter);
                quint32 count = tmpCaesar.count(ch.toLatin1());
                qreal expected = tmpCaesar.size() * letterProbabilities[letter - 97];
                qreal value = qPow((count - expected), 2) / expected;
                chiSquared += value;
            }
            qDebug() << QString("Letter %1, \tChi-Squared %2").arg(QChar(shift + 97)).arg(chiSquared);
            chiSquareds.append(chiSquared);
        }

        quint32 index = 0;
        for(int c = 1; c < chiSquareds.length(); c++){
            if(chiSquareds.at(c) < chiSquareds.at(index)){
                index = c;
            }
        }
        QChar keyChar = QChar(index + 97);
        qDebug() << QString("Vigenere Letter Found: %1").arg(keyChar) << endl;
        key->append(keyChar);
    }
}

void Vigenere::Decrypt(QByteArray* cipher, QByteArray* key, QByteArray* result)
{
    for(quint32 c = 0; c < cipher->length(); c++){
        quint32 tmpChar = (*cipher)[c];
        if(tmpChar < 97 || tmpChar > 122){
            //qDebug() << QString("Invalid character of value %1 detected").arg(tmpChar);
            cipher->remove(c, 1);
            break;
        }
        quint32 tmp = tmpChar - key->at(c % key->length()) + 97;
        if(tmp < 97){
            tmp += 26;
        }
        result->append(tmp);
    }
}

void Vigenere::Encrypt(QByteArray* plaintext, QByteArray* key, QByteArray* result)
{
    for(quint32 c = 0; c < plaintext->length(); c++){
        quint32 tmpChar = (*plaintext)[c];
        if(tmpChar < 97 || tmpChar > 122){
            //qDebug() << QString("Invalid character of value %1 detected").arg(tmpChar);
            plaintext->remove(c, 1);
            break;
        }
        quint32 tmp = tmpChar + key->at(c % key->length()) - 97;
        if(tmp > 122){
            tmp -= 26;
        }
        result->append(tmp);
    }
}
