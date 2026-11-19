# Politique de sécurité

## Versions prises en charge

Seule la dernière version publiée reçoit des correctifs de sécurité.

## Signaler une vulnérabilité

**Ne publiez pas de vulnérabilité dans une issue publique.**

Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt → **Report a vulnerability**
(<https://github.com/N4ole/cryptage/security/advisories/new>).

Merci d'indiquer :

- la version concernée (et le système d'exploitation) ;
- une description du problème et de son impact ;
- les étapes de reproduction ou une preuve de concept ;
- si possible, une proposition de correctif.

N'incluez **jamais** de mot de passe ni de fichier contenant des données réelles.

## Délais indicatifs

- Accusé de réception : sous 7 jours.
- Première évaluation : sous 14 jours.
- Publication d'un correctif et d'un avis de sécurité (GitHub Security Advisory)
  dès que possible, avec mention du rapporteur s'il le souhaite.

## Périmètre

Sont notamment dans le périmètre : faiblesses du format de fichier, de la dérivation de
clé, de l'authentification des données, fuite de secrets (mémoire, journaux, fichiers
temporaires), écriture non atomique.

Hors périmètre : attaques nécessitant un accès complet à la machine pendant
l'utilisation (enregistreur de frappe, logiciel malveillant), mots de passe faibles
choisis par l'utilisateur.
