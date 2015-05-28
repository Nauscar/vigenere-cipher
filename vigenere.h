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
    void Import(QString*);
    QByteArray* GetCipher();
    quint32 GetCipherLength();
    void Solve(QString*);
    void Decrypt(QByteArray*, QByteArray*, QByteArray*);
    void Encrypt(QByteArray*, QByteArray*, QByteArray*);
private:
    QByteArray cipher;

    quint32 probableKeyLength();
    double indexOfCoincidence(QByteArray*);
    void setCaesars(QList<QByteArray>*, quint32);
    void findKey(QByteArray*, quint32);
};

#endif // VIGENERE_H
