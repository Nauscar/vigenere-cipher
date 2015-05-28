#include <QCoreApplication>
#include <QDebug>
#include "vigenere.h"

void selEncrypt(Vigenere*);
void selDecrypt(Vigenere*);
void selCryptanalysis(Vigenere*);
void getParameter(QByteArray*, QString*);
bool verifyInput(QByteArray*);

QTextStream stream(stdin);
QTextStream output(stdout);

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Vigenere* vigenere = new Vigenere();

    QString input;


    while(input.toInt() != -1){
        output << "1. \tEncrypt" << endl;
        output << "2. \tDecrypt" << endl;
        output << "3. \tCryptanalysis" << endl;
        output << "-1. \tExit" << endl << endl;
        QString input = stream.readLine();
        switch(input.toInt()){
        case 1:
            selEncrypt(vigenere);
            break;
        case 2:
            selDecrypt(vigenere);
            break;
        case 3:
            selCryptanalysis(vigenere);
            break;
        case -1:
            delete vigenere;
            qDebug() << "Exit";
            return a.exec();
        default:
            output << "Invalid input" << endl;
            break;
        }
    }
}

void selEncrypt(Vigenere* vigenere)
{
    QByteArray key;
    QString keyLabel = QString("key");
    getParameter(&key, &keyLabel);

    QByteArray plaintext;
    QString plaintextLabel = QString("plaintext");
    getParameter(&plaintext, &plaintextLabel);

    QByteArray cipher;
    vigenere->Encrypt(&plaintext, &key, &cipher);
    qDebug() << cipher << endl;
}

void selDecrypt(Vigenere* vigenere)
{
    QByteArray key;
    QString keyLabel = QString("key");
    getParameter(&key, &keyLabel);

    QByteArray cipher;
    QString cipherLabel = QString("cipher");
    getParameter(&cipher, &cipherLabel);

    QByteArray plaintext;
    vigenere->Decrypt(&cipher, &key, &plaintext);
    qDebug() << plaintext << endl;
}

void selCryptanalysis(Vigenere* vigenere)
{
    output << "Enter filename to analyse. [Default=\"download-ciphertext.cgi\"]:" << endl;
    QString input = stream.readLine();
    if(input == ""){
        input = QString("download-ciphertext.cgi");
    }
    output << "Enter destination filename. [Default=\"plaintext.txt\"]:" << endl;
    QString destination = stream.readLine();
    if(destination == ""){
        destination = QString("plaintext.txt");
    }

    vigenere->Import(&input);
    //qDebug() << *vigenere.GetCipher();
    vigenere->Solve(&destination);
}

void getParameter(QByteArray* input, QString* label)
{
    do{
    output << QString("Input %1 [a-z]:").arg(*label) << endl;
    *input = stream.readLine().toStdString().c_str();
    } while(!verifyInput(input));
}

bool verifyInput(QByteArray* input)
{
    foreach(QChar inputChar, *input){
        if(inputChar.toLatin1() < 97 || inputChar.toLatin1() > 122){
            qDebug() << "Invalid input";
            return false;
        }
    }

    return true;
}
