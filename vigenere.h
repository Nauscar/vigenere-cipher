#ifndef VIGENERE_H
#define VIGENERE_H

#include <QDataStream>
#include <QDebug>
#include <QFile>
#include <QtMath>

class Vigenere
{
public:
    Vigenere();
    int Import();
    QByteArray* GetCipher();
    quint32 GetCipherLength();
    void Solve();
    void Decrypt(QByteArray*, QByteArray*, QByteArray*);
private:
    QByteArray cipher;

    quint32 probableKeyLength();
    double indexOfCoincidence(QByteArray*);
    void setCaesars(QList<QByteArray>*, quint32);
    void findKey(QByteArray*, quint32);
    QByteArray caesarDecrypt(QByteArray, QChar);
};

#endif // VIGENERE_H
