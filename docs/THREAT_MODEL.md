# Modèle de menaces

Actifs : tokens API F5 XC des utilisateurs, configuration WAAP du tenant (LB, WAF,
policies), journaux de sécurité, journal d'audit du serveur.

| STRIDE | Menace | Contrôle | Où |
|---|---|---|---|
| Spoofing | Appel HTTP sans identité, ou avec un token partagé du serveur | Chaque appelant envoie son propre token XC (`X-F5XC-API-Token`) ; démarrage refusé si `F5XC_API_TOKEN` est défini en mode HTTP ; requête sans token refusée | `config.py`, `runtime.py` |
| Spoofing | DNS rebinding vers le serveur local | Bind loopback uniquement ; protection Host/Origin du SDK MCP (403) | `config.py`, `server.py` |
| Tampering | Arguments du modèle (injection de chemin, de requête de logs) | Schémas stricts (enums fermées, regex de nom XC, bornes) ; segments d'URL revalidés ; valeurs de filtres sans `" { } \` | `tools/common.py`, `catalog.py` |
| Tampering | Payload modifié entre plan et apply | Le corps est construit et conservé côté serveur ; `apply_plan` ne prend qu'un `plan_id` aléatoire, à usage unique, lié à l'identité, avec un TTL ; refus si l'objet a changé depuis le plan | `plans.py`, `tools/changes.py` |
| Repudiation | Action non imputable | Audit JSON par appel : identité pseudonymisée, outil, hash des arguments, statut, code d'erreur, latence | `audit.py`, `runtime.py` |
| Information disclosure | Fuite de token ou de secret de configuration | Token jamais journalisé ni renvoyé ; erreurs à code stable sans corps amont ; secrets masqués (clés privées, `clear_secret_info`...) ; vue `spec` interdite pour les objets sensibles | `errors.py`, `sanitize.py` |
| Information disclosure | Données personnelles des logs (en-têtes, corps, cookies) | Projection sur une liste fermée de champs ; tout le reste est supprimé | `sanitize.py` |
| Denial of service | Agent en boucle, réponse énorme | Limite de débit par identité et globale, plafond par session, détection de boucle, taille de réponse plafonnée en streaming, fenêtre de temps bornée, pas de retry | `guardrails.py`, `xc_client.py` |
| Elevation of privilege | Outil d'écriture utilisé en mode lecture | Les outils d'écriture ne sont pas enregistrés en mode read (absents de `tools/list`), test dédié | `runtime.py`, `tests/test_registry.py` |
| Elevation of privilege | Le serveur agit avec plus de droits que l'utilisateur | Le token de l'utilisateur est utilisé tel quel : le RBAC XC reste la frontière finale | `xc_client.py` |
| Elevation of privilege | Prompt injection via les données XC (description, user-agent, chemin) poussant à une écriture | Texte nettoyé et borné, résultats marqués `untrusted_content` ; toute écriture exige une confirmation humaine qui retape le nom de l'objet | `sanitize.py`, `tools/changes.py` |

## Risques résiduels assumés

- **Injection de prompt.** Le nettoyage réduit la surface sans l'éliminer : un texte de
  200 caractères peut encore contenir une instruction. La vraie barrière est la
  confirmation humaine des écritures.
- **Elicitation automatique.** Un client MCP peut répondre seul à une demande
  d'elicitation (agent autonome). Utilise un client qui montre réellement la question à
  l'utilisateur.
- **Token non vérifié localement.** En mode HTTP, le serveur ne valide pas le token :
  c'est XC qui le fait. Une identité « inventée » n'obtient qu'un 401 de XC, mais elle
  consomme du quota de débit (d'où la limite globale).
- **Heuristiques de posture.** Les constats de `get_lb_security_posture` sont des
  heuristiques, pas un audit de conformité.
