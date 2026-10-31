# Modèle de menaces

Actifs : tokens API F5 XC des utilisateurs, configuration WAAP du tenant (LB, WAF,
policies), journaux de sécurité, journal d'audit du serveur.

| STRIDE | Menace | Contrôle | Où |
|---|---|---|---|
| Spoofing | Appel HTTP sans identité, ou avec un token partagé du serveur | Chaque appelant envoie son propre token XC (`X-F5XC-API-Token`) ; démarrage refusé si `F5XC_API_TOKEN` est défini en mode HTTP ; le token est résolu en utilisateur nominatif par XC (`whoami`) avant tout appel ; service credentials refusées par défaut | `config.py`, `runtime.py`, `identity.py` |
| Spoofing / DoS | Faux tokens pour épuiser les quotas ou solliciter XC | Validation `whoami` avant tout quota ; cache négatif 60 s ; limite globale des validations de tokens inconnus ; limite par IP sur le reverse proxy | `identity.py`, README |
| Tampering / EoP | Configuration injectée par des variables d'environnement génériques (`MODE=write`, `API_TOKEN`) | Seuls les noms `F5XC_*` sont lus (`populate_by_name=False`) ; test et règle Semgrep | `config.py` |
| Spoofing | DNS rebinding vers le serveur local | Bind loopback par défaut (hors loopback seulement avec `F5XC_MCP_ALLOW_NON_LOOPBACK_BIND` et une liste `Host` explicite) ; protection Host/Origin du SDK MCP (403) | `config.py`, `server.py` |
| Tampering | Arguments du modèle (injection de chemin, de requête de logs) | Schémas stricts (enums fermées, regex de nom XC, bornes) ; segments d'URL revalidés ; valeurs de filtres sans `" { } \` | `tools/common.py`, `catalog.py` |
| Tampering | Payload modifié entre plan et apply | Le corps est construit et conservé côté serveur ; `apply_plan` ne prend qu'un `plan_id` aléatoire, à usage unique, lié à l'utilisateur, avec un TTL | `plans.py`, `tools/changes.py` |
| Tampering | Modification concurrente entre plan et apply (spec, `disable`, labels, objet recréé) | Empreinte spec + métadonnées réécrites par le PUT + `uid`, recalculée juste avant le PUT ; plan refusé si elle diffère | `tools/changes.py` |
| Elevation of privilege | Exclusion WAF large présentée comme anodine | Chaque règle nouvelle ou modifiée est évaluée ; HIGH RISK sauf signatures précises sur domaine et chemin précis | `tools/changes.py` |
| Elevation of privilege | Création d'un objet déjà référencé par son nom (activation immédiate) | Recherche des références dans le namespace (LB, service policies actives, origin pools selon le type) ; HIGH RISK si trouvé ou si la recherche est incomplète | `tools/changes.py` |
| Tampering | L'humain valide un nom et non un changement ; diff tronqué ou maquillé | Le message d'élicitation, construit par le serveur, contient le diff complet, le SHA-256 du corps et un bandeau HIGH RISK ; diff exhaustif feuille par feuille (règles appariées par nom, ordre signalé), valeurs et clés échappées en JSON ; un diff trop gros ou touchant un secret refuse le plan ; HIGH RISK exige de retaper le préfixe du hash | `plans.py`, `tools/changes.py` |
| Elevation of privilege | Réécriture arbitraire d'un LB, d'une origin pool ou d'une policy | Pas de remplacement générique : outils ciblés seulement ; création limitée aux objets inertes tant qu'ils ne sont pas référencés | `tools/changes.py` |
| Repudiation | Action non imputable | Audit JSON nominatif (utilisateur XC, UUID, session aléatoire) : `tool_call` pour chaque appel, puis `plan_created`, `plan_confirmation` (issue) et `plan_applied` reliés par `plan_id` et `body_sha256` ; fichier en `0600`, compatible rotation ; `query_audit_logs` XC comme contrôle compensatoire | `audit.py`, `runtime.py` |
| Information disclosure | Fuite de token ou de secret de configuration | Token jamais journalisé ni renvoyé ; erreurs à code stable sans corps amont ; secrets masqués (clés privées, `clear_secret_info`...) ; vue `spec` interdite pour les objets sensibles | `errors.py`, `sanitize.py` |
| Information disclosure | Données personnelles des logs (en-têtes, corps, cookies) | Projection sur une liste fermée de champs ; tout le reste est supprimé | `sanitize.py` |
| Denial of service | Agent en boucle, réponse énorme | Limite de débit par identité et globale, plafond par session, détection de boucle, taille de réponse plafonnée en streaming, fenêtre de temps bornée, pas de retry | `guardrails.py`, `xc_client.py` |
| Elevation of privilege | Outil d'écriture utilisé en mode lecture | Les outils d'écriture ne sont pas enregistrés en mode read (absents de `tools/list`), test dédié | `runtime.py`, `tests/test_registry.py` |
| Elevation of privilege | Le serveur agit avec plus de droits que l'utilisateur | Le token de l'utilisateur est utilisé tel quel : le RBAC XC reste la frontière finale | `xc_client.py` |
| Elevation of privilege | Prompt injection via les données XC (description, user-agent, chemin) poussant à une écriture | Texte nettoyé et borné ; caractères invisibles supprimés par catégorie Unicode (dont Unicode Tags) ; résultats marqués `untrusted_content` ; toute écriture exige une confirmation humaine sur le diff complet affiché par le serveur | `sanitize.py`, `tools/changes.py` |
| Repudiation / disponibilité | Écriture erronée impossible à défaire, arrêt d'urgence lent | Interrupteur d'arrêt par fichier (sans redémarrage) ; état « avant » archivé et `plan_revert` revu ; `plan_applied` corrélable à l'audit log XC | `tools/changes.py` |

## Risques résiduels assumés

- **Injection de prompt.** Le nettoyage réduit la surface sans l'éliminer : un texte de
  200 caractères peut encore contenir une instruction. La vraie barrière est la
  confirmation humaine des écritures.
- **Elicitation automatique.** Un client MCP peut répondre seul à une demande
  d'elicitation (agent autonome). Utilise un client qui montre réellement la question à
  l'utilisateur.
- **Validation de tokens inconnus.** Un client anonyme peut encore consommer le budget
  global de validations (`F5XC_MCP_AUTH_RATE_PER_MINUTE`) et bloquer temporairement
  l'arrivée de nouveaux utilisateurs. Les utilisateurs déjà en cache ne sont pas
  touchés. La limite par IP sur le reverse proxy est la parade.
- **Fenêtre entre contrôle et PUT.** L'API XC publiée n'offre ni `resource_version` ni
  `If-Match` sur le PUT (vérifié dans la spec brute : `docs/evidence/openapi-facts.json`). Une modification faite par un tiers
  entre la relecture de contrôle et le PUT (quelques dizaines de millisecondes) serait
  écrasée. Elle reste visible dans `query_audit_logs` côté XC.
- **Recherche de références à la création.** Elle couvre les types qui référencent
  habituellement l'objet créé, dans le même namespace, dans la limite de 50 objets par
  type (au-delà, HIGH RISK « incomplète »). Un référent d'un autre type ou d'un autre
  namespace ne serait pas vu.
- **Risque des `ip_prefix_set`.** Le serveur ne sait pas si une liste sert à bloquer ou
  à autoriser : toute modification est marquée HIGH RISK par précaution.
- **Image de base.** 44 vulnérabilités HIGH Debian sans correctif publié (util-linux,
  sqlite, ncurses…) restent dans l'image trixie ; le processus ne les invoque pas. La CI
  bloque dès qu'un correctif existe.
- **Exclusions WAF.** Les suffixes publics viennent de la Public Suffix List embarquée :
  elle doit être rafraîchie (`scripts/update_psl.py`) pour connaître les nouveaux suffixes.
- **Revert.** N'importe quel utilisateur autorisé en écriture sur le namespace peut annuler
  le changement d'un autre (décision d'exploitation) ; c'est signalé HIGH RISK avec l'auteur
  d'origine. Les fichiers de rollback contiennent la configuration (sans secrets) : `0600`.
- **Heuristiques de posture.** Les constats de `get_lb_security_posture` sont des
  heuristiques, pas un audit de conformité.
