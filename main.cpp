#include <QCoreApplication>
#include <QDebug>
#include "vigenere.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Vigenere* vigenere = new Vigenere();
    vigenere->Import();
    //qDebug() << *vigenere.GetCipher();
    vigenere->Solve();

    qDebug() << "Exit";
    return a.exec();
}
