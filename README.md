#Q1 : le nom de l'algorithme de chiffrement est cipherXOR. Cette algorithme à des failles car il utilise la meme clef de chiffrement de manière repeté pour de long message. Donc si je connais une partie du message, je peux facilement retrouver la clef, en essayant de retrouver le message déjà connus, ensuite nous aurons acces au message complet.

#Q2 : Lorsqu'on hache la clef et le sel nous n'obtenons pas une bonne sécurité, des attaquants pourrait attaquer par force brute afin de connaître la clef. L'objectif du HMAC est de garantir l'intégrité et l'authenticité même si ce le HMAC utilise une fonction d'hachage ce n'est pas une fonction de dérivation de clé.

#Q3 : Il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent car cela permet de ne pas ecraser un token qui peut être précédent. De cela il y aura un potentiel soucis de déchiffrement et alors perdre des datas.

#Q4 : Pour vérifier si la clé est correcte, on peut effectuer une dérivation de la clé avec le sel et comparer le résultat obtenu au token enregistré. Si les deux tokens correspondent, cela signifie que la clé est valide, et nous pouvons alors procéder au déchiffrement des données.